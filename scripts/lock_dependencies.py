"""用固定 uv 生成跨平台、带哈希的依赖锁；操作说明见 docs/DEPENDENCIES.md。"""
import argparse
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = '0.11.19'
LOCKS = [('requirements', '3.12'), ('requirements-dev', '3.12'),
         ('requirements-legacy', '3.9'), ('requirements-lock', '3.12')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uv', default='uv', help='固定版本 uv 的可执行文件路径')
    parser.add_argument('--upgrade', action='store_true', help='重新选择所有允许的依赖版本')
    args = parser.parse_args()
    version = subprocess.check_output([args.uv, '--version'], text=True).split()[1]
    if version != UV_VERSION:
        parser.error('需要 uv ' + UV_VERSION)
    # Avoid local index/override/config settings silently changing the public locks.
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(('UV_', 'PIP_'))}
    env['UV_NO_CONFIG'] = '1'
    env['UV_CACHE_DIR'] = str(ROOT / '.local' / 'uv-cache')
    for name, python in LOCKS:
        subprocess.run([
            args.uv, 'pip', 'compile', name + '.in', '--output-file', name + '.txt',
            '--universal', '--python-version', python, '--no-python-downloads',
            '--generate-hashes', '--only-binary', ':all:', '--no-emit-index-url',
            '--default-index', 'https://pypi.org/simple',
            '--custom-compile-command', 'python scripts/lock_dependencies.py',
            *(['--upgrade'] if args.upgrade else []),
        ], cwd=ROOT, env=env, check=True, stdout=subprocess.DEVNULL)
        print('Generated ' + name + '.txt', flush=True)


if __name__ == '__main__':
    main()
