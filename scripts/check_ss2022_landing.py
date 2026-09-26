"""Loopback integration helpers for the disposable real-systemd runtime test."""
import contextlib
import os
import socket
import socketserver
import subprocess
import threading
import time
import uuid

from agent.deployment_spec import spec_hash
from agent.landing_spec import METHOD
from agent.runtime_engine import write_json
from agent.runtime_spec import revision
from deployment_store import new_landing_spec


def job(spec, remove=False):
    identifier = uuid.uuid4().hex
    action = 'landing.remove' if remove else 'landing.apply'
    payload = {'deployment_id': 'b' * 32, 'revision': 1, 'spec_hash': spec_hash(spec)}
    return {'id': identifier, 'type': action, 'payload': payload, 'deployment': spec,
            'deployment_revision': revision(identifier, action, payload)}


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class TcpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            data = self.request.recv(1024)
            if data:
                self.request.sendall(data)
        except OSError:
            pass


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(data, self.client_address)


@contextlib.contextmanager
def echo_servers():
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), TcpEcho) as tcp, \
            socketserver.ThreadingUDPServer(('127.0.0.1', 0), UdpEcho) as udp:
        workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in (tcp, udp)]
        for worker in workers:
            worker.start()
        try:
            yield tcp.server_address[1], udp.server_address[1]
        finally:
            tcp.shutdown()
            udp.shutdown()
            for worker in workers:
                worker.join(timeout=5)


def relay_check(engine, backend, spec, expected=True):
    """Use the real client implementation, not a hand-written SS cipher."""
    with echo_servers() as (tcp_echo, udp_echo):
        tcp_port, udp_port = free_port(), free_port(socket.SOCK_DGRAM)
        config = {'log': {'disabled': True}, 'inbounds': [
            {'type': 'direct', 'tag': 'tcp-test', 'listen': '127.0.0.1', 'listen_port': tcp_port,
             'network': 'tcp', 'override_address': '127.0.0.1', 'override_port': tcp_echo},
            {'type': 'direct', 'tag': 'udp-test', 'listen': '127.0.0.1', 'listen_port': udp_port,
             'network': 'udp', 'override_address': '127.0.0.1', 'override_port': udp_echo}],
            'outbounds': [{'type': 'shadowsocks', 'tag': 'landing', 'server': '127.0.0.1',
                           'server_port': spec['listen_port'], 'method': METHOD, 'password': spec['password']}]}
        path = engine.root / 'test-client.json'
        write_json(path, config)
        os.chown(path, 0, backend.gid)
        path.chmod(0o640)
        binary = engine.root / engine.pointer('current') / 'sing-box'
        command = [str(binary), 'run', '-c', str(path)]
        process = subprocess.Popen(command, user=backend.uid, group=backend.gid, extra_groups=[],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError('SS2022 test client exited')
                try:
                    with socket.create_connection(('127.0.0.1', tcp_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError('SS2022 test client did not start')
            payload = b'proxyforge-loopback-' + uuid.uuid4().hex.encode()
            with socket.create_connection(('127.0.0.1', tcp_port), timeout=3) as client:
                client.sendall(payload)
                try:
                    received = client.recv(1024)
                except OSError:
                    received = b''
                assert (received == payload) == expected, 'SS2022 TCP authentication/relay failed'
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(3)
                client.sendto(payload, ('127.0.0.1', udp_port))
                try:
                    received, _ = client.recvfrom(1024)
                except socket.timeout:
                    received = b''
                assert (received == payload) == expected, 'SS2022 UDP authentication/relay failed'
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            path.unlink(missing_ok=True)


def check_landing(engine, backend):
    spec = new_landing_spec({'name': 'Disposable landing', 'server': 'landing.example.com',
                             'listen_port': free_port(), 'method': METHOD})
    change = job(spec)
    assert engine.apply(change)['output']['running']
    before = engine.pointer('current')
    engine.apply(change)
    assert engine.pointer('current') == before
    relay_check(engine, backend, spec)
    wrong = {**spec, 'password': new_landing_spec({key: spec[key] for key in ('name', 'server', 'listen_port', 'method')})['password']}
    relay_check(engine, backend, wrong, expected=False)
    # Test both TCP and UDP bind failures; each must restore the previous listener.
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET6, kind) as occupied:
            occupied.bind(('::', 0))
            if kind == socket.SOCK_STREAM:
                occupied.listen()
            try:
                engine.apply(job({**spec, 'listen_port': occupied.getsockname()[1]}))
            except (ValueError, subprocess.CalledProcessError):
                pass
            else:
                raise AssertionError('Expected landing bind conflict')
        assert engine.pointer('current') == before
        assert backend.matches(engine.root / before)
    relay_check(engine, backend, spec)
    assert engine.apply(job({}, remove=True))['output']['running']
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET6, kind) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(('::', spec['listen_port']))
    print('SS2022: real TCP/UDP relay, wrong-key rejection, replay, bind-conflict rollback and removal passed')
