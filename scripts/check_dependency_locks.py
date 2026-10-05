"""临时环境验证依赖重复安装、生产/开发一致性及哈希拒绝；不修改当前环境。"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import venv


ROOT = Path(__file__).resolve().parents[1]


def run(python, *args, **kwargs):
    return subprocess.run([str(python), *args], check=True, text=True, **kwargs)


def snapshot(python):
    result = run(python, '-c',
                 'import importlib.metadata as m, json; '
                 'print(json.dumps({d.metadata["Name"].lower().replace("_", "-"): d.version '
                 'for d in m.distributions() if d.metadata["Name"].lower() '
                 'not in ("pip", "setuptools")}))', capture_output=True)
    return json.loads(result.stdout)


def main():
    if sys.version_info[:2] not in ((3, 12), (3, 13)):
        raise SystemExit('Controller 锁验收需要 Python 3.12 或 3.13')
    with tempfile.TemporaryDirectory(prefix='proxyforge-locks-') as temp:
        root = Path(temp)
        snapshots = []
        for index in range(2):
            env = root / str(index)
            venv.EnvBuilder(with_pip=True).create(env)
            python = env / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
            states = []
            for lock in ('requirements.txt', 'requirements-dev.txt'):
                run(python, '-m', 'pip', '--isolated', 'install', '--quiet',
                    '--disable-pip-version-check', '--index-url', 'https://pypi.org/simple',
                    '--require-hashes', '--only-binary=:all:', '-r', str(ROOT / lock))
                run(python, '-m', 'pip', 'check')
                states.append(snapshot(python))
            if any(states[1].get(name) != version for name, version in states[0].items()):
                raise RuntimeError('Development lock changed a production dependency')
            snapshots.append(states)
        if snapshots[0] != snapshots[1]:
            raise RuntimeError('Repeated installs produced different dependency versions')

        # A real download with deliberately incorrect hashes must fail closed.
        text = (ROOT / 'requirements.txt').read_text(encoding='utf-8')
        block = re.search(r'(?m)^h11==[^\n]+\n(?:[ \t]+[^\n]*\n)*', text)
        if not block:
            raise RuntimeError('Update hash rejection fixture: h11 no longer in production lock')
        invalid = re.sub(r'sha256:[0-9a-f]{64}', 'sha256:' + '0' * 64, block.group())
        bad_lock = root / 'invalid.txt'
        bad_lock.write_text(invalid, encoding='utf-8')
        result = subprocess.run([
            str(python), '-m', 'pip', '--isolated', 'download', '--no-cache-dir',
            '--disable-pip-version-check', '--index-url', 'https://pypi.org/simple',
            '--require-hashes', '--only-binary=:all:', '--no-deps',
            '--dest', str(root / 'rejected'), '-r', str(bad_lock),
        ], text=True, capture_output=True)
        if result.returncode == 0 or 'DO NOT MATCH THE HASHES' not in result.stderr:
            raise RuntimeError('Invalid hash was not rejected with a hash mismatch')
        print('Repeated production/development installs, pip check and hash rejection passed')


if __name__ == '__main__':
    main()
