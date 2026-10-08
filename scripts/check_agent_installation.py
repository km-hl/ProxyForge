"""一次性 GitHub Linux 环境：执行控制台命令，验证真实 HTTPS 注册和 systemd 心跳。

必须显式传 --disposable-system-test；会安装 Agent、测试 CA 并添加测试 hosts。
仅用于独立 CI runner，不在开发机、已有 Agent 或生产服务器上运行。
"""
import argparse
from contextlib import contextmanager
import datetime
import json
import os
from pathlib import Path
import platform
import pty
import pwd
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import termios
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
import uvicorn

from proxyforge.control.agent_api import attach_agent_routes
from proxyforge.control.control_store import ControlStore

HOST = 'proxyforge-install-ci.example'
CA_PATH = Path('/usr/local/share/ca-certificates/proxyforge-install-ci.crt')
CONFIG = Path('/etc/proxyforge-agent/config.json')


def verify_platform(expected_version, expected_arch, expected_os='ubuntu'):
    """Fail before host writes if the matrix label does not match the real environment."""
    release = platform.freedesktop_os_release()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if (release.get('ID'), release.get('VERSION_ID'), arch) != (expected_os, expected_version, expected_arch):
        raise SystemExit('Runner OS/architecture does not match the installation matrix')
    # Test Controller and Agent interpreters are separate; always verify the
    # distro system Python, including Ubuntu 22.04's 3.10 and Debian 12's 3.11.
    system_python = json.loads(subprocess.check_output([
        '/usr/bin/python3', '-I', '-c',
        'import json,platform,sys; print(json.dumps([list(sys.version_info[:3]),platform.machine()]))',
    ], text=True, timeout=10))
    if (system_python[0][:2] != {('ubuntu', '22.04'): [3, 10], ('ubuntu', '24.04'): [3, 12],
                                    ('debian', '12'): [3, 11], ('debian', '13'): [3, 13]}[(expected_os, expected_version)]
            or system_python[1].lower() != platform.machine().lower()):
        raise SystemExit('Unexpected system Python version or architecture')
    print('Verified installation platform:', release['ID'], expected_version, arch,
          'system Python', '.'.join(map(str, system_python[0])), flush=True)


@contextmanager
def ci_opt_permissions():
    # Observed GitHub Ubuntu image: /opt is root-owned but mode 0777 for
    # tool setup. Adjust only this directory on the dedicated disposable VM,
    # without recursion/ownership changes, and restore its mode afterwards.
    path = Path('/opt')
    current = path.lstat()
    mode = stat.S_IMODE(current.st_mode)
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.geteuid() == 0
    assert stat.S_ISDIR(current.st_mode) and current.st_uid == 0 and mode in (0o755, 0o777)
    try:
        if mode == 0o777:
            path.chmod(0o755)
        yield
    finally:
        if mode == 0o777:
            path.chmod(mode)


def command_pty(command, token=None):
    """Run exactly the copied command. Token enters a non-echoing TTY only."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-c', command],
                  {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'})
    output = bytearray()
    sent = False
    status = None
    deadline = time.monotonic() + 150
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    block = os.read(fd, 65536)
                except OSError:
                    break
                if not block:
                    break
                output.extend(block)
                assert len(output) < 1024 * 1024, 'Unexpected installer output volume'
            if b'One-time registration token (hidden): ' in output and not sent:
                assert token is not None, 'Unexpected credential prompt'
                assert not termios.tcgetattr(fd)[3] & termios.ECHO, 'Credential input is echoing'
                os.write(fd, token.encode() + b'\n')
                sent = True
            child, result = os.waitpid(pid, os.WNOHANG)
            if child:
                status = result
                break
        if status is None:
            # EOF generally precedes waitpid readiness by a scheduler tick.
            while time.monotonic() < deadline:
                child, result = os.waitpid(pid, os.WNOHANG)
                if child:
                    status = result
                    break
                time.sleep(0.05)
        assert status is not None, 'Installer timed out'
        assert token is None or token.encode() not in output, 'Credential leaked to terminal output'
        return os.waitstatus_to_exitcode(status), bytes(output), sent
    finally:
        if status is None:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)


def certificate(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .sign(key, hashes.SHA256()))
    key_path, cert_path = root / 'key.pem', root / 'cert.pem'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    CA_PATH.write_bytes(cert_path.read_bytes())
    subprocess.run(['update-ca-certificates'], check=True, stdout=subprocess.DEVNULL)
    with Path('/etc/hosts').open('a') as output:
        output.write('\n127.0.0.1 ' + HOST + '\n')
    return key_path, cert_path


def check_helper(command, client, headers, agent_id):
    """Opt in with the console command, then cross the real Unix peer boundary."""
    before = CONFIG.read_bytes()
    status, output, sent = command_pty(command)
    assert status == 0 and not sent, 'Explicit helper bootstrap failed'
    assert CONFIG.read_bytes() == before, 'Helper changed Agent identity/credentials'
    account = pwd.getpwnam('proxyforge-agent')
    info = Path('/run/proxyforge-runtime.sock').stat()
    assert stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
    assert info.st_gid == account.pw_gid and stat.S_IMODE(info.st_mode) == 0o660
    subprocess.run(['systemctl', 'is-active', '--quiet', 'proxyforge-runtime.socket'], check=True)
    current = Path('/var/lib/proxyforge-runtime/current')
    assert not current.exists(), 'Opt-in unexpectedly installed sing-box'
    # Installed Agent + distro Python under its service UID. stdin carries a
    # public job schema only, never an enrollment or Agent credential.
    code = ("import json,sys; sys.path.insert(0, '/opt/proxyforge-agent'); "
            "from agent.runtime_client import execute; "
            "print(json.dumps(execute(json.load(sys.stdin), lambda: None)))")
    from agent.runtime_spec import RELEASE, revision
    import uuid

    def request(action, *, authorized=True):
        identifier = uuid.uuid4().hex
        payload = {'version': RELEASE['version']} if action == 'singbox.install' else {}
        job = {'id': identifier, 'type': action, 'payload': payload,
               'deployment_revision': revision(identifier, action, payload)}
        invocation = ['/usr/bin/python3', '-I', '-c', code]
        if authorized:
            invocation = ['runuser', '-u', 'proxyforge-agent', '--', *invocation]
        result = subprocess.run(invocation, input=json.dumps(job), capture_output=True,
                                text=True, check=True, timeout=660)
        return json.loads(result.stdout)

    denied = request('singbox.install', authorized=False)
    assert denied == {'status': 'failed', 'output': None, 'error': 'runtime_failed'}
    assert not current.exists(), 'Unauthorized peer changed runtime'
    for action in ('singbox.install', 'singbox.restart', 'singbox.rollback', 'singbox.stop', 'singbox.start'):
        result = request(action)
        assert result['status'] == 'success' and result['error'] is None, 'Real helper action failed: ' + action
        state = result['output']
        assert state['installed'] and state['running'] == (action != 'singbox.stop')
        assert state['version'] == RELEASE['version']
    pid = subprocess.check_output(['systemctl', 'show', '--property=MainPID', '--value',
                                   'proxyforge-singbox.service'], text=True, timeout=10).strip()
    actual_uid = Path('/proc/' + pid).stat().st_uid
    assert actual_uid == pwd.getpwnam('proxyforge-singbox').pw_uid and actual_uid != 0
    assert json.loads((current / 'config.json').read_text())['inbounds'] == [], 'Unsolicited listener'
    assert CONFIG.read_bytes() == before
    status, _, sent = command_pty(command)
    assert status != 0 and not sent, 'Repeated helper installation was accepted'
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        metadata = client.get('/api/agents', headers=headers).json()['agents'][0]['metadata']
        if metadata.get('runtime_protocol_version') == 1 and metadata['singbox']['running']:
            break
        time.sleep(0.25)
    else:
        raise AssertionError('No helper capability/runtime heartbeat received')
    assert all(metadata[name] == 1 for name in ('deployment_protocol_version', 'landing_protocol_version',
                                               'chain_protocol_version'))
    assert client.get('/api/agents', headers=headers).json()['agents'][0]['id'] == agent_id
    journals = subprocess.check_output(['journalctl', '-u', 'proxyforge-runtime', '-u', 'proxyforge-singbox',
                                       '--no-pager'])
    assert json.loads(before)['token'].encode() not in output + journals, 'Helper leaked Agent credentials'
    print('PASS: explicit helper bootstrap, real UID/socket authorization, native sing-box lifecycle, capability heartbeat',
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-system-test', action='store_true', required=True)
    distribution = parser.add_mutually_exclusive_group(required=True)
    distribution.add_argument('--expected-ubuntu', choices=('22.04', '24.04'))
    distribution.add_argument('--expected-debian', choices=('12', '13'))
    parser.add_argument('--expected-arch', choices=('amd64', 'arm64'), required=True)
    parser.add_argument('--check-helper', action='store_true', help='普通安装后显式启用并验证 helper')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or not Path('/run/systemd/system').is_dir():
        raise SystemExit('Only a dedicated disposable GitHub Linux root runner is supported')
    expected_os = 'debian' if args.expected_debian else 'ubuntu'
    expected_version = args.expected_debian or args.expected_ubuntu
    verify_platform(expected_version, args.expected_arch, expected_os)
    for path in ('/opt/proxyforge-agent', '/etc/proxyforge-agent',
                 '/etc/systemd/system/proxyforge-agent.service', '/var/lib/proxyforge-runtime',
                 '/etc/systemd/system/proxyforge-runtime.service', '/run/proxyforge-runtime.sock', str(CA_PATH)):
        assert not os.path.lexists(path), 'Refusing pre-existing installation or test CA'
    assert HOST not in Path('/etc/hosts').read_text(), 'Refusing existing test hosts entry'
    try:
        pwd.getpwnam('proxyforge-agent')
    except KeyError:
        pass
    else:
        raise SystemExit('Refusing pre-existing Agent account')
    for name in ('/', '/var', '/var/lib', '/opt', '/etc', '/etc/systemd', '/etc/systemd/system', '/run'):
        current = Path(name).lstat()
        print('CI parent permissions:', name, current.st_uid, oct(stat.S_IMODE(current.st_mode)), flush=True)
    with ci_opt_permissions(), tempfile.TemporaryDirectory(prefix='proxyforge-install-ci-') as temporary:
        root = Path(temporary)
        key, cert = certificate(root)
        store = ControlStore(root / 'control.db')
        app = FastAPI()
        admin_token = secrets.token_urlsafe(32)

        def admin(authorization: str = Header(default='')):
            if authorization != 'Bearer ' + admin_token:
                raise HTTPException(status_code=401)

        attach_agent_routes(app, admin, lambda: store)
        heartbeat = threading.Event()

        @app.middleware('http')
        async def observe_heartbeat(request, call_next):
            response = await call_next(request)
            if request.url.path == '/api/agent/heartbeat' and response.status_code == 200:
                heartbeat.set()
            return response

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False,
                                                  ssl_keyfile=str(key), ssl_certfile=str(cert)))
            worker = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
            worker.start()
            deadline = time.monotonic() + 10
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.05)
            assert server.started, 'HTTPS fixture did not start'
            os.environ['PROXYFORGE_PUBLIC_URL'] = 'https://' + HOST + ':' + str(sock.getsockname()[1])
            try:
                with TestClient(app) as client:
                    headers = {'Authorization': 'Bearer ' + admin_token}
                    info = client.get('/api/agents/install-command', headers=headers).json()
                    command = info['commands']['install']
                    registration = client.post('/api/agents/registration-tokens', headers=headers,
                                               json={'name': 'Disposable installation acceptance'}).json()
                    token = registration['registration_token']
                    assert token not in command
                    print('Executing the console installation command with a real controlling TTY', flush=True)
                    status, output, sent = command_pty(command, token)
                    if status != 0 or not sent:
                        # Installer errors contain only fixed paths/status. Still redact
                        # both credential formats and the exact supplied token defensively.
                        diagnostic = output.decode('utf-8', errors='replace').replace(token, '[redacted]')
                        diagnostic = re.sub(r'pf(?:reg|agt)_[A-Za-z0-9_-]+', '[redacted]', diagnostic)
                        print(diagnostic[-4096:], flush=True)
                        raise AssertionError('Real installer failed')
                    assert heartbeat.wait(45), 'Service started but HTTPS heartbeat was not received'
                    agents = client.get('/api/agents', headers=headers).json()['agents']
                    assert len(agents) == 1 and agents[0]['status'] == 'online'
                    metadata = agents[0]['metadata']
                    assert (metadata['os'], metadata['os_version'], metadata['arch']) == (
                        expected_os, expected_version, args.expected_arch), 'Installed Agent reported a different platform'
                    assert metadata['supported'] and metadata['agent_version'] == info['agent_version']
                    saved = json.loads(CONFIG.read_text())
                    assert saved['controller'] == info['controller_url'] and saved['agent_id'] == agents[0]['id']
                    assert not saved['allow_insecure'] and saved['ca_file'] is None
                    assert stat.S_IMODE(CONFIG.stat().st_mode) == 0o600
                    assert CONFIG.stat().st_uid == pwd.getpwnam('proxyforge-agent').pw_uid
                    subprocess.run(['systemctl', 'is-active', '--quiet', 'proxyforge-agent'], check=True)
                    for path in ('/var/lib/proxyforge-runtime', '/run/proxyforge-runtime.sock',
                                 '/etc/systemd/system/proxyforge-runtime.service',
                                 '/etc/systemd/system/proxyforge-runtime.socket', '/opt/proxyforge-agent/bin/sing-box'):
                        assert not os.path.lexists(path), 'Optional runtime was enabled implicitly'
                    journals = subprocess.check_output(['journalctl', '-u', 'proxyforge-agent', '--no-pager'])
                    for secret in (token.encode(), saved['token'].encode()):
                        assert secret not in output and secret not in journals, 'Credential leaked in logs'
                        for path in Path('/proc').glob('[0-9]*/cmdline'):
                            try:
                                args = path.read_bytes()
                            except (FileNotFoundError, ProcessLookupError):
                                continue
                            assert secret not in args, 'Credential leaked in process arguments'
                        history = Path('/root/.bash_history')
                        assert not history.exists() or secret not in history.read_bytes(), 'Credential leaked in history'
                    before = CONFIG.read_bytes()
                    status, _, sent = command_pty(command)
                    assert status != 0 and not sent and CONFIG.read_bytes() == before, 'Existing installation was overwritten'
                    # The exact single-use credential is rejected after successful enrollment.
                    from agent.system_info import collect
                    response = client.post('/api/agent/register', json={
                        **collect(saved['instance_id']), 'registration_token': token})
                    assert response.status_code == 401
                    print('PASS: installation, trusted HTTPS heartbeat, private credentials, no helper, repeat refusal', flush=True)
                    if args.check_helper:
                        check_helper(info['commands']['runtime'], client, headers, agents[0]['id'])
            finally:
                if args.check_helper:
                    subprocess.run(['systemctl', 'stop', 'proxyforge-runtime.socket', 'proxyforge-runtime.service',
                                    'proxyforge-singbox.service'], check=False, stdout=subprocess.DEVNULL)
                subprocess.run(['systemctl', 'stop', 'proxyforge-agent'], check=False, stdout=subprocess.DEVNULL)
                server.should_exit = True
                worker.join(timeout=10)


if __name__ == '__main__':
    main()
