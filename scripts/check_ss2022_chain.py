"""Real Reality -> SS2022 loopback test; only the TLS camouflage target is a fixture."""
import contextlib
from datetime import datetime, timedelta, timezone
import json
import os
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from agent.deployment_spec import spec_hash
from agent.landing_spec import METHOD, runtime_config as landing_config
from agent.runtime_engine import write_json
from agent.runtime_spec import revision
from proxyforge.control.deployment_store import new_spec, new_landing_spec
from scripts.check_ss2022_landing import free_port, relay_check


def job(spec, remove=False):
    identifier = uuid.uuid4().hex
    action = 'chain.remove' if remove else 'chain.apply'
    payload = {'deployment_id': 'c' * 32, 'revision': 1, 'spec_hash': spec_hash(spec)}
    return {'id': identifier, 'type': action, 'payload': payload, 'deployment': spec,
            'deployment_revision': revision(identifier, action, payload)}


@contextlib.contextmanager
def tls_target(root):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'www.example.com')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1)).sign(key, hashes.SHA256()))
    key_path, cert_path = root / 'tls-test.key', root / 'tls-test.pem'
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as output:
        output.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve('X25519')
    context.load_cert_chain(cert_path, key_path)
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                with context.wrap_socket(self.request, server_side=True) as connection:
                    connection.recv(1024)
            except OSError:
                pass
    try:
        with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                yield server.server_address[1]
            finally:
                server.shutdown()
                worker.join(timeout=5)
    finally:
        key_path.unlink(missing_ok=True)
        cert_path.unlink(missing_ok=True)


@contextlib.contextmanager
def landing_process(engine, backend, spec):
    path = engine.root / 'test-landing.json'
    write_json(path, landing_config(spec))
    os.chown(path, 0, backend.gid)
    path.chmod(0o640)
    binary = engine.root / 'cache' / 'sing-box'
    process = subprocess.Popen([str(binary), 'run', '-c', str(path)], user=backend.uid, group=backend.gid,
                               extra_groups=[], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError('Landing fixture exited')
            try:
                with socket.create_connection(('127.0.0.1', spec['listen_port']), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError('Landing fixture did not start')
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        path.unlink(missing_ok=True)


def client_outbound(spec):
    return {'type': 'vless', 'tag': 'entry', 'server': '127.0.0.1', 'server_port': spec['listen_port'],
            'uuid': spec['uuid'], 'flow': 'xtls-rprx-vision', 'tls': {'enabled': True,
            'server_name': spec['server_name'], 'utls': {'enabled': True, 'fingerprint': 'chrome'},
            'reality': {'enabled': True, 'public_key': spec['public_key'], 'short_id': spec['short_id']}}}


def check_chain(engine, backend):
    direct = new_spec({'name': 'Direct', 'server': 'entry.example.com', 'server_name': 'www.example.com', 'listen_port': free_port()})
    entry = new_spec({**{key: direct[key] for key in ('server', 'server_name')}, 'name': 'Via landing', 'listen_port': free_port()})
    landing = new_landing_spec({'name': 'Landing', 'server': '127.0.0.1', 'listen_port': free_port(), 'method': METHOD})
    spec = {'direct': direct, 'chain': {'entry': entry, 'landing': landing}}
    original_check = backend.check
    with tls_target(engine.root) as handshake_port:
        def fixture_check(release):
            original_check(release)  # Validate the exact generated production config first.
            path = release / 'config.json'
            config = json.loads(path.read_text())
            # Also validate a domain endpoint without dialing external DNS.
            if any(outbound['type'] == 'shadowsocks' for outbound in config['outbounds']):
                domain_config = json.loads(json.dumps(config))
                domain_config['outbounds'][1]['server'] = 'landing.example.com'
                write_json(path, domain_config)
                original_check(release)
            for inbound in config['inbounds']:
                inbound['tls']['reality']['handshake'] = {'server': '127.0.0.1', 'server_port': handshake_port}
            write_json(path, config)
            original_check(release)
        backend.check = fixture_check
        try:
            with landing_process(engine, backend, landing):
                change = job(spec)
                assert engine.apply(change)['output']['running']
                previous = engine.pointer('current')
                engine.apply(change)
                assert engine.pointer('current') == previous
                relay_check(engine, backend, landing, outbound=client_outbound(direct))
                relay_check(engine, backend, landing, outbound=client_outbound(entry))
                with socket.socket(socket.AF_INET6) as occupied:
                    occupied.bind(('::', 0))
                    occupied.listen()
                    broken = {'direct': direct, 'chain': {'entry': {**entry, 'listen_port': occupied.getsockname()[1]}, 'landing': landing}}
                    try:
                        engine.apply(job(broken))
                    except (ValueError, subprocess.CalledProcessError):
                        pass
                    else:
                        raise AssertionError('Expected chain bind conflict')
                assert engine.pointer('current') == previous
                relay_check(engine, backend, landing, outbound=client_outbound(entry))
            # No fallback to direct: only the explicit direct node still reaches the echo.
            relay_check(engine, backend, landing, expected=False, outbound=client_outbound(entry))
            relay_check(engine, backend, landing, outbound=client_outbound(direct))
            assert engine.apply(job({'direct': direct, 'chain': None}, remove=True))['output']['running']
            relay_check(engine, backend, landing, outbound=client_outbound(direct))
            with socket.socket(socket.AF_INET6) as probe:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('::', entry['listen_port']))
        finally:
            backend.check = original_check
    print('Chain: real Reality TCP/UDP via SS2022, direct coexistence, no fallback, rollback, replay and removal passed')
