"""Root-owned immutable releases and recoverable activation of one fixed unit."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time

from .runtime_download import download_binary
from .runtime_spec import RELEASE, CONFIG_ACTIONS, validate_runtime_job
from .deployment_spec import runtime_config
from .landing_spec import runtime_config as landing_config

UNIT = 'proxyforge-singbox.service'
EMPTY_CONFIG = {'log': {'level': 'warn'}, 'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}]}


class RuntimeCancelled(Exception):
    pass


class RollbackFailed(Exception):
    pass


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value, mode=0o600):
    temporary = path.with_name('.' + path.name + '.' + secrets.token_hex(8))
    try:
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class SystemBackend:
    def __init__(self):
        import pwd
        account = pwd.getpwnam('proxyforge-singbox')
        self.uid, self.gid = account.pw_uid, account.pw_gid

    def check(self, release):
        # Candidate config is readable by the isolated runtime user, never world-readable.
        os.chown(release, 0, self.gid)
        release.chmod(0o755)
        os.chown(release / 'config.json', 0, self.gid)
        (release / 'config.json').chmod(0o640)
        result = subprocess.run([str(release / 'sing-box'), 'check', '-c', str(release / 'config.json')],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20,
                                user=self.uid, group=self.gid, extra_groups=[])
        if result.returncode:
            raise ValueError('Runtime configuration check failed')
        result = subprocess.run([str(release / 'sing-box'), 'version'], capture_output=True, text=True,
                                timeout=5, user=self.uid, group=self.gid, extra_groups=[])
        first = result.stdout.splitlines()[0] if result.stdout else ''
        expected = json.loads((release / 'release.json').read_text())['version']
        if result.returncode or first != 'sing-box version ' + expected:
            raise ValueError('Runtime version check failed')

    def active(self):
        return subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0

    def matches(self, release):
        if not self.active():
            return False
        value = subprocess.run(['/usr/bin/systemctl', 'show', '--property=MainPID', '--value', UNIT],
                               capture_output=True, text=True, timeout=5)
        pid = value.stdout.strip()
        if value.returncode or not pid.isdigit() or int(pid) <= 1:
            return False
        try:
            if Path('/proc/' + pid + '/exe').resolve(strict=True) != (release / 'sing-box').resolve(strict=True):
                return False
            config = json.loads((release / 'config.json').read_text())
            for inbound in config.get('inbounds', []):
                with socket.create_connection(('::1', inbound['listen_port']), timeout=1):
                    pass
            return True
        except (OSError, ValueError, KeyError):
            return False

    def stop(self):
        subprocess.run(['/usr/bin/systemctl', 'stop', UNIT], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.active():
            raise ValueError('Runtime did not stop')

    def activate(self, release):
        if self.matches(release):
            return
        # A never-started unit may have no loaded failure state yet.
        subprocess.run(['/usr/bin/systemctl', 'reset-failed', UNIT], check=False, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['/usr/bin/systemctl', 'restart', UNIT], check=True, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(3):
            time.sleep(0.5)
            if not self.matches(release):
                raise ValueError('Runtime failed health verification')


class RuntimeEngine:
    def __init__(self, root, backend, arch, downloader=download_binary):
        self.root, self.backend, self.arch, self.downloader = Path(root), backend, arch, downloader
        (self.root / 'releases').mkdir(exist_ok=True)

    def pointer(self, name):
        path = self.root / name
        if not path.is_symlink():
            if path.exists():
                raise ValueError('Managed pointer is not a symlink')
            return None
        target = os.readlink(path)
        if not re.fullmatch(r'releases/[a-f0-9]{32}', target):
            raise ValueError('Invalid managed release pointer')
        release = self.root / target
        if release.is_symlink() or not release.is_dir():
            raise ValueError('Invalid managed release')
        return target

    def set_pointer(self, name, target):
        path = self.root / name
        if target is None:
            path.unlink(missing_ok=True)
        else:
            temporary = self.root / ('.' + name + '.' + secrets.token_hex(8))
            try:
                os.symlink(target, temporary)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        sync_directory(self.root)

    def receipts(self):
        path = self.root / 'receipts.json'
        return json.loads(path.read_text()) if path.exists() else {}

    def status(self):
        current = self.pointer('current')
        if not current:
            return {'installed': False, 'running': False, 'version': '', 'status': 'not_installed'}
        running = self.backend.matches(self.root / current)
        version = json.loads((self.root / current / 'release.json').read_text())['version']
        return {'installed': True, 'running': running, 'version': version, 'status': 'running' if running else 'stopped'}

    def finish(self, transaction):
        output = self.status()
        if not output['installed'] or output['running'] != transaction['running']:
            raise ValueError('Runtime lost health before commit')
        self.set_pointer('previous', transaction['old'] if transaction['new'] != transaction['old'] else transaction['previous'])
        result = {'status': 'success', 'output': output, 'error': None}
        receipts = self.receipts()
        receipts[transaction['job']['id']] = {'revision': transaction['job']['deployment_revision'], 'result': result}
        write_json(self.root / 'receipts.json', dict(list(receipts.items())[-128:]))
        (self.root / 'transaction.json').unlink()
        sync_directory(self.root)
        self.prune()
        return result

    def rollback(self, transaction):
        try:
            self.set_pointer('current', transaction['old'])
            self.set_pointer('previous', transaction['previous'])
            if transaction['was_running'] and transaction['old']:
                self.backend.activate(self.root / transaction['old'])
            else:
                self.backend.stop()
            (self.root / 'transaction.json').unlink()
            sync_directory(self.root)
            self.prune()
        except Exception:
            # Preserve the intent and releases for local repair; no further mutation until recovery succeeds.
            raise RollbackFailed() from None

    def recover(self):
        path = self.root / 'transaction.json'
        if not path.exists():
            return
        transaction = json.loads(path.read_text())
        validate_runtime_job(transaction['job'])
        receipts = self.receipts()
        if transaction['job']['id'] in receipts:
            path.unlink()
            sync_directory(self.root)
            return
        reached = self.pointer('current') == transaction['new'] and (
            self.backend.matches(self.root / transaction['new']) if transaction['running'] else not self.backend.active())
        if reached:
            self.finish(transaction)
        else:
            self.rollback(transaction)

    def prune(self):
        keep = {self.pointer('current'), self.pointer('previous')}
        for path in (self.root / 'releases').iterdir():
            if re.fullmatch(r'[a-f0-9]{32}', path.name) and 'releases/' + path.name not in keep:
                if path.is_symlink() or not path.is_dir():
                    raise ValueError('Invalid managed release directory')
                shutil.rmtree(path)

    def apply(self, job, guard=lambda: None):
        validate_runtime_job(job)
        self.recover()
        receipt = self.receipts().get(job['id'])
        if receipt:
            if receipt['revision'] != job['deployment_revision']:
                raise ValueError('Job identity changed')
            return receipt['result']
        guard()
        current, previous = self.pointer('current'), self.pointer('previous')
        was_running = self.backend.active()
        action = job['type']
        if action not in ('singbox.install', *CONFIG_ACTIONS) and not current:
            raise ValueError('Runtime is not installed')
        if action == 'singbox.rollback' and not previous:
            raise ValueError('No previous release')
        new = current
        running = action != 'singbox.stop'
        if action == 'singbox.rollback':
            running = was_running
        already_running = bool(current and self.backend.matches(self.root / current))
        same_version = bool(current and json.loads((self.root / current / 'release.json').read_text())['version'] == RELEASE['version'])
        unchanged = already_running and (action == 'singbox.start' or (action == 'singbox.install' and same_version))
        if unchanged:
            self.backend.check(self.root / current)
        if action != 'singbox.stop' and not unchanged:
            new = 'releases/' + job['id']
            candidate = self.root / new
            if candidate.exists():
                # An interrupted pre-activation staging directory is never reused.
                if candidate.is_symlink() or new in (current, previous):
                    raise ValueError('Release identity collision')
                shutil.rmtree(candidate)
            candidate.mkdir(mode=0o750)
            try:
                source = previous if action == 'singbox.rollback' else current
                if action == 'singbox.install' or (action in CONFIG_ACTIONS and not current):
                    self.downloader(candidate, self.arch, guard)
                    release_info = {'version': RELEASE['version']}
                else:
                    shutil.copy2(self.root / source / 'sing-box', candidate / 'sing-box')
                    release_info = json.loads((self.root / source / 'release.json').read_text())
                config = json.loads((self.root / source / 'config.json').read_text()) if source else EMPTY_CONFIG
                if action == 'deployment.apply':
                    config = runtime_config(job['deployment'])
                elif action == 'landing.apply':
                    config = landing_config(job['deployment'])
                elif action in ('deployment.remove', 'landing.remove'):
                    config = EMPTY_CONFIG
                write_json(candidate / 'config.json', config)
                write_json(candidate / 'release.json', release_info, 0o644)
                self.backend.check(candidate)
                # Copied binaries also need durability before publishing the generation.
                with (candidate / 'sing-box').open('rb') as binary:
                    os.fsync(binary.fileno())
                sync_directory(candidate)
                sync_directory(candidate.parent)
                guard()
            except BaseException:
                shutil.rmtree(candidate)
                raise
        transaction = {'job': {key: job[key] for key in ('id', 'type', 'payload', 'deployment_revision')},
                       'old': current, 'previous': previous, 'new': new, 'was_running': was_running, 'running': running}
        if action in CONFIG_ACTIONS:
            transaction['job']['deployment'] = job['deployment']
        write_json(self.root / 'transaction.json', transaction)
        try:
            guard()
            self.set_pointer('current', new)
            if running:
                if not self.backend.matches(self.root / new):
                    self.backend.activate(self.root / new)
            else:
                self.backend.stop()
            return self.finish(transaction)
        except Exception:
            # If the receipt is durable, commit has happened; do not undo a successful action.
            if job['id'] not in self.receipts():
                self.rollback(transaction)
            raise
