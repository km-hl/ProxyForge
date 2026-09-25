"""Disposable Linux CI systemd integration. Never run on a deployed Agent host."""
import argparse
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.runtime_download import download_binary
from agent.runtime_engine import RuntimeEngine, SystemBackend, UNIT
from agent.runtime_spec import RELEASE, revision


def job(action):
    identifier = uuid.uuid4().hex
    payload = {'version': RELEASE['version']} if action == 'singbox.install' else {}
    return {'id': identifier, 'type': action, 'payload': payload,
            'deployment_revision': revision(identifier, action, payload)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-system-test', action='store_true', required=True)
    parser.parse_args()
    if os.geteuid() != 0 or Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise SystemExit('Requires disposable Linux root with systemd')
    unit_path = Path('/etc/systemd/system') / UNIT
    state = subprocess.run(['systemctl', 'show', '--property=LoadState', '--value', UNIT], capture_output=True, text=True)
    if unit_path.exists() or unit_path.is_symlink() or state.stdout.strip() != 'not-found':
        raise SystemExit('Refusing to replace any existing runtime unit')
    try:
        pwd.getpwnam('proxyforge-singbox')
    except KeyError:
        pass
    else:
        raise SystemExit('Refusing to use an existing runtime account')
    # PrivateTmp in the real unit deliberately hides /tmp from the service.
    with tempfile.TemporaryDirectory(prefix='proxyforge-system-test-', dir='/var/lib') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        cache = root / 'cache'
        cache.mkdir()
        download_binary(cache, 'amd64')
        subprocess.run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'proxyforge-singbox'], check=True)
        try:
            unit = (Path(__file__).resolve().parents[1] / 'agent/proxyforge-singbox.service').read_text()
            unit_path.write_text(unit.replace('/var/lib/proxyforge-runtime', str(root)))
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            def cached_download(directory, arch, guard):
                guard()
                shutil.copy2(cache / 'sing-box', directory / 'sing-box')
            backend = SystemBackend()
            engine = RuntimeEngine(root, backend, 'amd64', cached_download)
            initial = job('singbox.install')
            assert engine.apply(initial)['output']['running']
            first = engine.pointer('current')
            engine.apply(initial)
            assert engine.pointer('current') == first
            engine.apply(job('singbox.install'))
            assert engine.pointer('current') == first
            engine.apply(job('singbox.restart'))
            assert engine.pointer('current') != first
            assert not engine.apply(job('singbox.stop'))['output']['running']
            assert engine.apply(job('singbox.start'))['output']['running']
            assert engine.apply(job('singbox.rollback'))['output']['running']
            previous = engine.pointer('current')
            activate = backend.activate
            attempts = []
            def fail_once(release):
                activate(release)
                attempts.append(1)
                if len(attempts) == 1:
                    raise ValueError('simulated failed health check')
            backend.activate = fail_once
            try:
                engine.apply(job('singbox.restart'))
            except ValueError:
                pass
            else:
                raise AssertionError('Expected failed activation')
            assert engine.pointer('current') == previous
            assert backend.matches(root / previous)
            print('Pinned sing-box ' + RELEASE['version'] + ': real check/start/restart/stop/rollback passed')
        finally:
            subprocess.run(['systemctl', 'stop', UNIT], check=False)
            unit_path.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'daemon-reload'], check=False)
            subprocess.run(['systemctl', 'reset-failed', UNIT], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(['userdel', 'proxyforge-singbox'], check=True)


if __name__ == '__main__':
    main()
