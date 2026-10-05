"""Controller 镜像启动与 Python 跨版本冷恢复演练；见 docs/PYTHON_RUNTIME.md。"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
DATA = Path('/app/data')
ADMIN = 'synthetic-runtime-admin-token'
SUBSCRIPTION = 'synthetic-runtime-subscription-token'
MANIFEST = '.runtime-test.json'
TEMPLATE = 'proxy-groups: []\nrules: ["MATCH,DIRECT"]\n'
METADATA = {'instance_id': 'a' * 32, 'protocol_version': 1}
LEGACY_IMAGE = ('python:3.9.25-slim-bookworm@sha256:'
                'a02e9c5406c416c504d6c9a1a306ff4080c3173f1008d192f953bd20382a2d5c')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fingerprints():
    return {str(path.relative_to(DATA)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in DATA.rglob('*') if path.is_file()
            and not path.name.startswith('proxyforge.db') and path.name != MANIFEST}


def seed():
    # Only called in a disposable container with a newly created empty volume.
    require(DATA.is_dir() and not any(DATA.iterdir()), 'Fixture volume must be empty')
    from cryptography.fernet import Fernet
    from proxyforge.config.template_store import TemplateStore
    from proxyforge.control.control_store import ControlStore
    from proxyforge.security.runtime_security import RuntimeConfigStore

    RuntimeConfigStore(DATA / 'config.json', DATA / 'admin_token.txt', environ={
        'ADMIN_TOKEN': ADMIN, 'SECRET_TOKEN': SUBSCRIPTION,
    }).load_or_create()
    (DATA / 'template.yaml').write_text('proxy-groups: []\nrules: []\n', encoding='utf-8')
    node = {'name': 'manual', 'type': 'ss', 'server': 'manual.example.com', 'port': 8388,
            'cipher': 'aes-128-gcm', 'password': 'synthetic-runtime-password'}
    history = TemplateStore(DATA / 'template.yaml')
    history.commit({'template.yaml': TEMPLATE, 'custom_nodes.yaml': json.dumps([node]),
                    'airports.yaml': '[]\n'})
    store = ControlStore(DATA / 'proxyforge.db')
    agents = []
    for name in ('active', 'revoked'):
        registration = store.issue_registration(name)
        agents.append(store.register(registration['registration_token'], METADATA, ''))
    store.revoke(agents[1]['agent_id'])
    key = Fernet.generate_key()
    (DATA / 'deployment.key').write_bytes(key)
    manifest = {'agents': agents, 'node': node, 'files': fingerprints(),
                'history': history.list_history(),
                'ciphertext': Fernet(key).encrypt(b'synthetic-runtime-secret').decode()}
    (DATA / MANIFEST).write_text(json.dumps(manifest), encoding='utf-8')


def request(path, authenticated=False):
    headers = {'Authorization': 'Bearer ' + ADMIN} if authenticated else {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(urllib.request.Request('http://127.0.0.1:8000' + path,
                                                     headers=headers), timeout=3)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        return response.status, response.read()


def check():
    from cryptography.fernet import Fernet
    import yaml
    from proxyforge.config.template_store import TemplateStore
    from proxyforge.control.control_store import ControlStore, UnauthorizedAgent

    manifest = json.loads((DATA / MANIFEST).read_text(encoding='utf-8'))
    deadline = time.monotonic() + 30
    while True:
        try:
            status, _ = request('/')
            require(status == 200, 'Web UI unavailable')
            break
        except (OSError, RuntimeError):
            if time.monotonic() >= deadline:
                raise RuntimeError('Controller did not become ready') from None
            time.sleep(0.2)
    require(request('/api/config')[0] == 401, 'Unauthenticated admin request accepted')
    status, body = request('/api/template', True)
    require(status == 200 and json.loads(body)['content'] == TEMPLATE, 'Template mismatch')
    status, body = request('/api/nodes', True)
    require(status == 200 and json.loads(body)['nodes'] == [
        dict(manifest['node'], _airport_name='_custom_nodes_')], 'Manual node mismatch')
    status, body = request('/sub?token=' + SUBSCRIPTION)
    require(status == 200, 'Subscription failed')
    require(any(node.get('server') == manifest['node']['server']
                and node.get('password') == manifest['node']['password']
                for node in yaml.safe_load(body)['proxies']), 'Subscription node missing')
    status, body = request('/api/agents', True)
    require(status == 200 and {item['id'] for item in json.loads(body)['agents']} == {
        item['agent_id'] for item in manifest['agents']}, 'Agent inventory mismatch')
    store = ControlStore(DATA / 'proxyforge.db')
    store.heartbeat(manifest['agents'][0]['agent_token'], METADATA, '')
    try:
        store.heartbeat(manifest['agents'][1]['agent_token'], METADATA, '')
    except UnauthorizedAgent:
        pass
    else:
        raise RuntimeError('Revoked credential accepted')
    with store.connection() as db:
        require(db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'SQLite corruption')
        require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'SQLite foreign key violation')
        require(db.execute('SELECT MAX(version) FROM schema_migrations').fetchone()[0] == 5,
                'Unexpected schema version')
    require(TemplateStore(DATA / 'template.yaml').list_history() == manifest['history'],
            'Template history changed')
    require(Fernet((DATA / 'deployment.key').read_bytes()).decrypt(
        manifest['ciphertext'].encode()) == b'synthetic-runtime-secret', 'Key mismatch')
    actual = fingerprints()
    require(all(actual.get(name) == value for name, value in manifest['files'].items()),
            'Persisted fixture file changed')
    print('Controller startup/recovery passed: Python ' + sys.version.split()[0] + ', schema 5')


def docker_rehearsal():
    suffix = uuid.uuid4().hex[:12]
    candidate, legacy = ['proxyforge-runtime-' + suffix + tag for tag in (':candidate', ':legacy')]
    original, restored = ['proxyforge-runtime-' + suffix + tag for tag in ('-source', '-restore')]
    containers = []
    volumes = []

    def docker(*args, **kwargs):
        return subprocess.run(['docker', *args], cwd=ROOT, check=True, timeout=600, **kwargs)

    def run(image, volume, *command):
        docker('run', '--rm', '--network', 'none', '-v', volume + ':/app/data', image, *command)

    def start_check_stop(image, volume):
        name = 'proxyforge-runtime-' + uuid.uuid4().hex[:12]
        containers.append(name)
        docker('run', '-d', '--name', name, '--network', 'none',
               '-v', volume + ':/app/data', image, stdout=subprocess.DEVNULL)
        docker('exec', name, 'python', 'scripts/check_controller_image.py', 'check')
        docker('stop', '--time', '10', name, stdout=subprocess.DEVNULL)

    try:
        docker('build', '--pull', '-t', candidate, '.')
        dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        base = dockerfile.splitlines()[0]
        require(base.startswith('FROM python:3.12.') and '@sha256:' in base,
                'Update migration fixture when production runtime changes')
        # Same application/schema, old interpreter with a compatible dependency lock.
        dockerfile = dockerfile.replace(base, 'FROM ' + LEGACY_IMAGE, 1)
        require('COPY requirements.txt .' in dockerfile, 'Update legacy lock COPY rule')
        dockerfile = dockerfile.replace('COPY requirements.txt .',
                                        'COPY requirements-legacy.txt ./requirements.txt', 1)
        docker('build', '--pull', '-t', legacy, '-f', '-', '.', input=dockerfile, text=True)
        docker('run', '--rm', '--network', 'none', candidate, 'python', '-m', 'pip', 'check')
        docker('run', '--rm', '--network', 'none', candidate, 'python', '-c',
               "import sys; assert sys.version_info[:2] == (3, 12)")
        for volume in (original, restored):
            docker('volume', 'create', volume, stdout=subprocess.DEVNULL)
            volumes.append(volume)
        run(legacy, original, 'python', 'scripts/check_controller_image.py', 'seed')
        start_check_stop(legacy, original)
        # Cold copy: all source writers have stopped. Include SQLite and the key.
        docker('run', '--rm', '--network', 'none', '-v', original + ':/source:ro',
               '-v', restored + ':/target', candidate, 'python', '-c',
               "import shutil; shutil.copytree('/source', '/target', dirs_exist_ok=True)")
        start_check_stop(candidate, restored)
        start_check_stop(candidate, restored)
        start_check_stop(legacy, restored)
    finally:
        # UUID-owned resources only; never prune unrelated Docker resources.
        for name in containers:
            subprocess.run(['docker', 'rm', '-f', name], check=False, timeout=30,
                           stdout=subprocess.DEVNULL)
        for volume in volumes:
            subprocess.run(['docker', 'volume', 'rm', volume], check=False, timeout=30,
                           stdout=subprocess.DEVNULL)
        subprocess.run(['docker', 'image', 'rm', candidate, legacy], check=False, timeout=30,
                       stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('docker', 'seed', 'check'))
    args = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    if args.phase == 'docker':
        docker_rehearsal()
    elif args.phase == 'seed':
        seed()
    else:
        check()
