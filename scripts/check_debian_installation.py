"""一次性 GitHub runner：用同架构 Debian systemd 容器执行真实安装验收。

仅用于独立可丢弃 CI VM；不挂载宿主机业务目录、不发布端口。
容器使用宿主机内核，因此不代表完整 Debian VM/裸机验收。
"""
import argparse
import os
from pathlib import Path
import platform
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGES = {
    '12': 'debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587',
    '13': 'debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f',
}


def verify_host(expected_arch):
    native = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0 or native != expected_arch:
        raise SystemExit('Only a dedicated disposable GitHub root runner with matching native architecture is supported')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-system-test', action='store_true', required=True)
    parser.add_argument('--expected-debian', choices=tuple(BASE_IMAGES), required=True)
    parser.add_argument('--expected-arch', choices=('amd64', 'arm64'), required=True)
    args = parser.parse_args()
    verify_host(args.expected_arch)
    identity = 'proxyforge-debian-test-' + uuid.uuid4().hex
    image = identity + ':test'
    subprocess.run(['docker', 'build', '--build-arg', 'BASE_IMAGE=' + BASE_IMAGES[args.expected_debian],
                    '-f', str(ROOT / 'tests/containers/debian-install.Dockerfile'), '-t', image, str(ROOT)],
                   check=True, timeout=600)
    machine = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Architecture}}', image],
                                      text=True, timeout=10).strip()
    if machine != args.expected_arch:
        raise SystemExit('Image architecture does not match native runner')
    try:
        # No host directories, Docker socket, ports or cgroup bind mounts.
        # The privileged container is confined to this disposable CI VM.
        subprocess.run(['docker', 'run', '-d', '--name', identity, '--privileged', '--cgroupns=private',
                        '--tmpfs', '/run', '--tmpfs', '/run/lock', '-e', 'GITHUB_ACTIONS=true', image],
                       check=True, timeout=30)
        for attempt in range(80):
            ready = subprocess.run(['docker', 'exec', identity, 'systemctl', 'is-system-running'],
                                   capture_output=True, text=True, timeout=10)
            if ready.stdout.strip() in {'running', 'degraded'}:
                break
            if attempt == 79:
                raise RuntimeError('Debian container systemd did not become ready')
            time.sleep(0.5)
        print('Native Debian systemd container ready:', args.expected_debian, machine, flush=True)
        subprocess.run(['docker', 'exec', identity, '/opt/controller-test/bin/python',
                        'scripts/check_agent_installation.py', '--disposable-system-test',
                        '--expected-debian', args.expected_debian, '--expected-arch', args.expected_arch],
                       check=True, timeout=240)
        print('PASS: native Debian userland/system Python/systemd/HTTPS; host kernel shared', flush=True)
    finally:
        subprocess.run(['docker', 'rm', '-f', identity], check=False, timeout=30, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
