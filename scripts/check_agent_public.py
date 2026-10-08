"""已授权的公网验收：仅在新建 KVM VM 安装 Agent，保留校验过的在线备份。

宿主机需要 Linux amd64/root、KVM、QEMU/cloud-localds/SSH 和 Docker Controller。
不重启或升级 Controller；不在宿主机安装 Agent。中文使用说明见 Debian 验收文档。
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from proxyforge.control.agent_installation import controller_url, render  # noqa: E402
from scripts import check_debian_vm_installation as vm_tools  # noqa: E402

# Reviewed historical production and current install anchors, not API-supplied trust.
ANCHORS = {
    '977b16b41e0d5332d933df007e7a683189c1fdc8': (
        '6e2e7ee39b85b3c3c6535a96ea7ac09ac1f86cbf',
        '0b0aea74ff770090bb35866327ed0af5af35372d0c8da0193c14e33a7aca23c5'),
    'da2550a923f3a64a7d1e932a56090a34966f6ab7': (
        '00d5a604499e5b22081bc280d4e1e3f0a69b650c',
        '28fa9a875ef5c5513960cfbe8be269fe4a7bd688bb119a62bf461a3625df91c2'),
}
TABLES = ('agents', 'jobs', 'deployments', 'chains')

# Session cookie is created and used inside the existing Controller. No secret argv/env.
BROKER = '''import json,sys,urllib.request,urllib.error
from pathlib import Path
sys.path.insert(0, '/app')
from proxyforge.security.runtime_security import create_session_token
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
data=json.load(sys.stdin)
cookie='proxyforge_session='+create_session_token(json.loads(Path('/app/data/config.json').read_text())['session_secret'],120)
body=None if data['payload'] is None else json.dumps(data['payload']).encode()
request=urllib.request.Request(data['base']+data['path'],data=body,method=data['method'],
 headers={'Cookie':cookie,'Origin':data['base'],'Content-Type':'application/json'})
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect()).open(request,timeout=25) as response:
  raw=response.read(1048577)
  if len(raw)>1048576: raise ValueError('response_limit')
  print(json.dumps({'status':response.status,'body':json.loads(raw) if raw else None}))
except urllib.error.HTTPError as exc:
 print(json.dumps({'status':exc.code,'body':None}))
'''


def quiet(command, *, payload=None, timeout=30):
    result = subprocess.run(command, input=payload, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Subprocess failed; private output withheld')
    return result.stdout


def api(container, base, method, path, payload=None, expected=200):
    value = json.loads(quiet(['docker', 'exec', '-i', container, 'python', '-c', BROKER],
                            payload=json.dumps({'base': base, 'method': method, 'path': path,
                                                'payload': payload}).encode(), timeout=35))
    if value['status'] != expected:
        raise RuntimeError('Public management API returned status ' + str(value['status']))
    return value['body']


def verified_commands(info, base, source):
    commit, digest = ANCHORS[source]
    commands = {action: render(commit, digest, action=action, server=base if action == 'install' else None)
                for action in ('install', 'runtime', 'check')}
    if (info.get('available') is not True or info.get('controller_url') != base
            or info.get('agent_version') != '0.6.0' or info.get('source_commit') != source
            or info.get('bootstrap_commit') != commit or info.get('bootstrap_sha256') != digest
            or info.get('commands') != commands):
        raise ValueError('Controller installation commands differ from reviewed anchors')
    return commands


def files_snapshot(data):
    result = {}
    for path in sorted(data.rglob('*')):
        info = path.lstat()
        if path.is_symlink() or info.st_dev != data.stat().st_dev:
            raise ValueError('Data contains a symlink or another filesystem')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Data contains a special file or hard link')
        relative = path.relative_to(data).as_posix()
        if relative in ('proxyforge.db', 'proxyforge.db-wal', 'proxyforge.db-shm'):
            continue
        result[relative] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'size': info.st_size, 'mode': stat.S_IMODE(info.st_mode),
                            'uid': info.st_uid, 'gid': info.st_gid}
    return result


def database_counts(path):
    with contextlib.closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or db.execute('PRAGMA foreign_key_check').fetchall():
            raise ValueError('Database integrity/foreign key check failed')
        if db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] != 5:
            raise ValueError('Expected database schema 5')
        return {table: db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] for table in TABLES}


def directory_snapshot(data):
    return {path.relative_to(data).as_posix(): {
        'mode': stat.S_IMODE(path.stat().st_mode), 'uid': path.stat().st_uid, 'gid': path.stat().st_gid}
        for path in [data, *sorted(data.rglob('*'))] if path.is_dir()}


def backup(data, destination):
    """Copy-only rehearsal of an online SQLite backup; no live restore or stop."""
    before = files_snapshot(data)
    directories = directory_snapshot(data)
    destination.mkdir(mode=0o700)
    copied = destination / 'data'
    shutil.copytree(data, copied, ignore=lambda directory, names: (
        {'proxyforge.db', 'proxyforge.db-wal', 'proxyforge.db-shm'} if Path(directory) == data else set()))
    source_db = data / 'proxyforge.db'
    source_info = source_db.lstat()
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink != 1:
        raise ValueError('Unsafe database file')
    with contextlib.closing(sqlite3.connect(source_db.as_uri() + '?mode=ro', uri=True)) as source, \
            contextlib.closing(sqlite3.connect(copied / 'proxyforge.db')) as target:
        source.backup(target)
    (copied / 'proxyforge.db').chmod(stat.S_IMODE(source_info.st_mode))
    if files_snapshot(data) != before or directory_snapshot(data) != directories:
        raise ValueError('Configuration changed during backup')
    counts = database_counts(copied / 'proxyforge.db')
    for name, info in before.items():
        if hashlib.sha256((copied / name).read_bytes()).hexdigest() != info['sha256']:
            raise ValueError('Backup read-back failed')
    manifest = {**before, 'proxyforge.db': {
        'sha256': hashlib.sha256((copied / 'proxyforge.db').read_bytes()).hexdigest(),
        'size': (copied / 'proxyforge.db').stat().st_size,
        'mode': stat.S_IMODE(source_info.st_mode), 'uid': source_info.st_uid, 'gid': source_info.st_gid}}
    archive = destination / 'data.tar'
    with tarfile.open(archive, 'x') as output:
        for name, info in directories.items():
            item = output.gettarinfo(str(data / name), arcname='data' if name == '.' else 'data/' + name)
            item.uid, item.gid, item.mode = info['uid'], info['gid'], info['mode']
            output.addfile(item)
        for name, info in manifest.items():
            item = output.gettarinfo(str(copied / name), arcname='data/' + name)
            item.uid, item.gid, item.mode = info['uid'], info['gid'], info['mode']
            with (copied / name).open('rb') as content:
                output.addfile(item, content)
    with tarfile.open(archive) as input_archive:
        expected_members = {'data/' + name for name in manifest} | {
            'data' if name == '.' else 'data/' + name for name in directories}
        if set(input_archive.getnames()) != expected_members:
            raise ValueError('Backup archive members changed')
        for name, info in directories.items():
            member = input_archive.getmember('data' if name == '.' else 'data/' + name)
            if not member.isdir() or (member.uid, member.gid, member.mode) != (info['uid'], info['gid'], info['mode']):
                raise ValueError('Backup directory ownership changed')
        for name, info in manifest.items():
            member = input_archive.getmember('data/' + name)
            if (member.uid, member.gid, member.mode) != (info['uid'], info['gid'], info['mode']):
                raise ValueError('Backup archive ownership changed')
            if hashlib.sha256(input_archive.extractfile(member).read()).hexdigest() != info['sha256']:
                raise ValueError('Backup archive SHA256 read-back failed')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (destination / 'manifest.json').write_text(json.dumps({'files': manifest, 'directories': directories, 'archive_sha256': digest,
                                                          'schema': 5, 'counts': counts}, indent=2))
    (destination / 'SHA256SUMS').write_text(digest + '  data.tar\n')
    print('PASS: private online backup, SHA256/read-back and copy-only database integrity', flush=True)
    return before, counts, digest


def owned(agent, name, instance_id=None):
    if (agent.get('name') != name or agent.get('role') != 'unassigned'
            or not re.fullmatch('[0-9a-f]{32}', agent.get('id', ''))
            or instance_id is not None and agent.get('instance_id') != instance_id):
        raise ValueError('Refusing to mutate an unowned or repurposed Agent')
    return agent['id']


def containers():
    identifiers = quiet(['docker', 'ps', '-q']).decode().split()
    records = json.loads(quiet(['docker', 'inspect', *identifiers]))
    return {record['Name']: (record['Id'], record['Image'], record['State']['StartedAt'], record['RestartCount'])
            for record in records}


def host_guard():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() != 0:
        raise ValueError('Public acceptance requires an authorized Linux amd64 root host')
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise ValueError('Public acceptance requires KVM; no production TCG fallback')
    for executable in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'ssh', 'ssh-keygen', 'docker'):
        if shutil.which(executable) is None:
            raise ValueError('Missing required host tool')
    available = int(re.search(r'MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text())[1])
    if available < 2 * 1024**2:
        raise ValueError('At least 2 GiB available host memory is required')


def private_parent(parent):
    if parent.resolve(strict=True) != parent:
        raise ValueError('Output parent must not contain symlinks or relative components')
    for path in (parent, *parent.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Output ancestors must be root-owned and not group/world writable')


def terminate(signum, frame):
    raise KeyboardInterrupt('Public acceptance interrupted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-vm', action='store_true', required=True)
    parser.add_argument('--controller-url', required=True)
    parser.add_argument('--controller-container', default='proxyforge')
    parser.add_argument('--expected-controller-image', required=True)
    parser.add_argument('--expected-source-commit', choices=tuple(ANCHORS), required=True)
    parser.add_argument('--output-dir', type=Path, required=True, help='新的 root 私有目录；保留备份及脱敏报告')
    args = parser.parse_args()
    os.umask(0o077)
    host_guard()
    signal.signal(signal.SIGTERM, terminate)
    base = controller_url(args.controller_url)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.expected_controller_image):
        raise ValueError('Expected an exact Controller image ID')
    container = args.controller_container
    record = json.loads(quiet(['docker', 'inspect', container]))[0]
    if record['Image'] != args.expected_controller_image or not record['State']['Running']:
        raise ValueError('Controller image/state differs from expected deployment')
    mounts = [Path(item['Source']) for item in record['Mounts'] if item['Destination'] == '/app/data'
              and item['Type'] == 'bind' and item['RW']]
    if len(mounts) != 1 or mounts[0].is_symlink():
        raise ValueError('Expected one authoritative data bind mount')
    data = mounts[0].resolve(strict=True)
    output = args.output_dir.absolute()
    private_parent(output.parent)
    if output.exists() or output.is_relative_to(data) or data.is_relative_to(output):
        raise ValueError('Output must be a new private directory outside Controller data')
    if shutil.disk_usage(output.parent).free < 3 * 1024**3:
        raise ValueError('At least 3 GiB free disk space is required')
    output.mkdir(mode=0o700)
    image_state = containers()
    commands = verified_commands(api(container, base, 'GET', '/api/agents/install-command'),
                                 base, args.expected_source_commit)
    before, counts, backup_sha = backup(data, output / 'backup')
    # This operator fixture is for the initial control-plane acceptance only.
    if any(counts.values()) or any(database_counts(data / 'proxyforge.db').values()):
        raise ValueError('Acceptance requires no existing Agent/jobs/deployments/chains')
    name = 'Public acceptance VM ' + uuid.uuid4().hex
    agent_id = instance_id = None
    report = {'schema': 5, 'agent_version': '0.6.0', 'source_commit': args.expected_source_commit,
              'controller_image': args.expected_controller_image, 'backup_sha256': backup_sha,
              'topology': 'same-host isolated Debian 12 amd64 KVM; real public HTTPS',
              'acceptance_passed': False, 'jobs': []}
    cleanup_ok = False
    try:
        with tempfile.TemporaryDirectory(prefix='proxyforge-public-') as directory:
            work = Path(directory)
            work.chmod(0o700)
            identity = 'proxyforge-public-' + uuid.uuid4().hex
            url, digest = vm_tools.image_url('12', 'amd64')
            vm_tools.download_image(url, digest, work / 'base.qcow2')
            quiet(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(work / 'base.qcow2'),
                   str(work / 'guest.qcow2'), '6G'])
            vm_tools.create_seed(work, identity)
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            (work / 'known_hosts').write_text(f'[127.0.0.1]:{port} ' + (work / 'host.pub').read_text())
            ssh = ['ssh', '-F', '/dev/null', '-p', str(port), '-i', str(work / 'client'),
                   '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(work / 'known_hosts'),
                   '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=ssh-ed25519',
                   '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', 'ci@127.0.0.1']
            qemu = vm_tools.qemu_command(work, 'amd64', port)
            qemu[qemu.index('-m') + 1], qemu[qemu.index('-smp') + 1] = '1024', '1'
            qemu[qemu.index('-machine') + 1] = 'q35,dump-guest-core=off'
            with (work / 'qemu.log').open('wb') as log:
                vm = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 240
                    while time.monotonic() < deadline:
                        if vm.poll() is not None:
                            raise RuntimeError('QEMU exited before SSH readiness')
                        ready = subprocess.run([*ssh, 'true'], capture_output=True, timeout=15)
                        if ready.returncode == 0:
                            break
                        time.sleep(5)
                    else:
                        raise TimeoutError('VM SSH readiness exceeded its budget')
                    vm_tools.wait_cloud_init(ssh, vm)
                    evidence = json.loads(quiet([*ssh, 'sudo /usr/bin/python3 -I -c ' + shlex.quote(vm_tools.PROBE)]))
                    vm_tools.verify_guest(evidence, '12', 'amd64', identity, platform.release())
                    report['kernel'] = evidence['kernel']
                    quiet([*ssh, 'sudo sh -c ' + shlex.quote('umask 077; cat > /opt/proxyforge-public-probe.py')],
                          payload=(ROOT / 'scripts/agent_public_guest.py').read_bytes())

                    def guest(action, **values):
                        result = json.loads(quiet([*ssh, 'sudo /usr/bin/python3 -I /opt/proxyforge-public-probe.py'],
                                                 payload=json.dumps({'identity': identity, 'server': base,
                                                                     'action': action, **values}).encode(), timeout=210))
                        return result

                    # Registration is never retried; issue only after a proven empty VM is ready.
                    registration = api(container, base, 'POST', '/api/agents/registration-tokens', {'name': name})
                    print('Executing verified public console installation command in the new VM', flush=True)
                    installed = guest('install', command=commands['install'], token=registration['registration_token'])
                    agent_id, instance_id = installed['agent_id'], installed['instance_id']
                    report['python'] = installed['python']

                    def agent():
                        item = api(container, base, 'GET', '/api/agents/' + agent_id)
                        owned(item, name, instance_id)
                        return item

                    def wait_agent(helper=False):
                        deadline = time.monotonic() + 75
                        while time.monotonic() < deadline:
                            item = agent()
                            meta = item['metadata']
                            if (item['status'] == 'online' and meta.get('runtime_protocol_version') == int(helper)):
                                if (meta['os'], meta['os_version'], meta['arch'], meta['agent_version'], meta['supported']) != (
                                        'debian', '12', 'amd64', '0.6.0', True):
                                    raise ValueError('Heartbeat platform/version differs from VM')
                                return
                            time.sleep(3)
                        raise TimeoutError('Public HTTPS heartbeat did not arrive')

                    def job(action, wanted, version=None):
                        agent()
                        path = '/api/agents/' + agent_id + '/jobs'
                        payload = {'request_id': uuid.uuid4().hex, 'type': action,
                                   'payload': {'version': version} if version else {}}
                        created = api(container, base, 'POST', path, payload)
                        duplicate = api(container, base, 'POST', path, payload)
                        if created['id'] != duplicate['id']:
                            raise ValueError('Job request idempotency failed')
                        deadline = time.monotonic() + 720
                        first_lease, renewed = None, False
                        while time.monotonic() < deadline:
                            item = next(row for row in api(container, base, 'GET', path)['jobs'] if row['id'] == created['id'])
                            if item.get('lease_until'):
                                if first_lease is None:
                                    first_lease = item['lease_until']
                                renewed |= item['lease_until'] > first_lease
                            if item['status'] in ('success', 'failed', 'cancelled'):
                                break
                            time.sleep(2)
                        else:
                            raise TimeoutError('Public queue job timed out')
                        if (item['status'] != 'success' or item['attempts'] != 1
                                or any(item[field] is None for field in ('assigned_at', 'started_at', 'finished_at'))
                                or item['result']['output']['status'] != wanted):
                            raise ValueError('Public queue/runtime action failed: ' + action)
                        report['jobs'].append({'type': action, 'status': item['status'], 'attempts': item['attempts'],
                                               'lease_renewal_observed': renewed})
                        print('PASS: public HTTPS queue claim/start/result, idempotency:', action, wanted,
                              'renewal observed:', renewed, flush=True)

                    wait_agent()
                    print('PASS: actual public HTTPS registration/heartbeat; ordinary Agent, hidden TTY, private identity', flush=True)
                    job('singbox.status', 'not_installed')
                    print('Explicitly enabling the verified helper inside the new VM', flush=True)
                    enabled = guest('helper', command=commands['runtime'])
                    if enabled['identity_sha256'] != installed['identity_sha256']:
                        raise ValueError('Helper changed Agent identity')
                    wait_agent(helper=True)
                    release = api(container, base, 'GET', '/api/agents/runtime/release')['version']
                    for action in ('install', 'restart', 'rollback', 'stop', 'start'):
                        job('singbox.' + action, 'stopped' if action == 'stop' else 'running', release if action == 'install' else None)
                    final = guest('probe')
                    if final['identity_sha256'] != installed['identity_sha256']:
                        raise ValueError('Queued actions changed Agent identity')
                    job('singbox.stop', 'stopped')
                    agent()
                    api(container, base, 'POST', '/api/agents/' + agent_id + '/revoke')
                    deadline = time.monotonic() + 75
                    while time.monotonic() < deadline:
                        if guest('revoked')['revoked_exit']:
                            report['revocation_exit_4'] = True
                            break
                        time.sleep(3)
                    else:
                        raise TimeoutError('Revoked Agent did not stop synchronization')
                    report['acceptance_passed'] = True
                finally:
                    vm.terminate()
                    try:
                        vm.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        vm.kill()
                        vm.wait(timeout=10)
    finally:
        # Recover only the unique named fixture if registration succeeded but reply was lost.
        candidates = [item for item in api(container, base, 'GET', '/api/agents')['agents'] if item['name'] == name]
        if len(candidates) > 1:
            raise ValueError('Ambiguous fixture cleanup; preserve backup and inspect manually')
        for item in candidates:
            identifier = owned(item, name, instance_id)
            if agent_id is not None and identifier != agent_id:
                raise ValueError('Fixture identity changed before cleanup')
            api(container, base, 'DELETE', '/api/agents/' + identifier, expected=204)
        cleanup_ok = (files_snapshot(data) == before and database_counts(data / 'proxyforge.db') == counts
                      and containers() == image_state)
        report['fixture_removed_and_business_unchanged'] = cleanup_ok
        (output / 'report.json').write_text(json.dumps(report, indent=2))
        if not cleanup_ok:
            raise ValueError('Post-acceptance configuration/container/data invariant failed')
        print('PASS: own VM/Agent/jobs removed; Controller/configuration and all running containers unchanged', flush=True)
    print('PASS: public Agent and Controller queue acceptance; private backup/report retained', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('FAIL: public acceptance (' + type(exc).__name__ + '); private diagnostic output withheld', file=sys.stderr)
        raise SystemExit(1)
