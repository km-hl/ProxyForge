"""一次性 GitHub runner：启动同架构、独立 Debian 内核的完整 VM 安装验收。

固定官方云镜像及 SHA512；仅通过回环 SSH 访问自己创建的临时 VM。
不要在开发机或生产服务器执行。临时 SSH 私钥、seed 和磁盘不上传。
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
# Independently reviewed against the dated official SHA512SUMS, 2026-10-08.
IMAGES = {
    ('12', 'amd64'): ('bookworm', '20261006-2623',
        'f631afb1d8123a29779f720f7f08a97e9f2ce5f5c705b8d9f753df8ed0c3afddeb34e4f254dfa41a6330e9a637387c80a8fe453d789446f9d8be7d7714d0ce7e'),
    ('12', 'arm64'): ('bookworm', '20261006-2623',
        '991f0dd77ee442eb2406568fc27c537190af0c78ab211b0e2adcf568cd203aebf696b94a05e64c7e00d3e05e0e532fdd941311e34ef862ad06bc1bc69a92a3fb'),
    ('13', 'amd64'): ('trixie', '20261001-2618',
        '6f0f93335bdef4ccf523c4317cc663ea52ca23b862667785f3d6d186ab4674a937385ccff0c55996b4b2e4c19e440cdf211e2a75ffa2f6548037ab43950c841d'),
    ('13', 'arm64'): ('trixie', '20261001-2618',
        '001e742c14a69f3f506c1663b271b4aeed7fa766f7471a13d49ee22d338b8a637b5206a75bf994435af7b26ce3794a255dcf22e312b0d4b8d7b7f96076fe925f'),
}


def verify_host(expected_arch):
    native = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if platform.system() != 'Linux' or os.environ.get('GITHUB_ACTIONS') != 'true' or native != expected_arch:
        raise SystemExit('Only a disposable GitHub Linux runner with matching native architecture is supported')


def image_url(version, arch):
    release, build, digest = IMAGES[version, arch]
    return (f'https://cloud.debian.org/images/cloud/{release}/{build}/'
            f'debian-{version}-generic-{arch}-{build}.qcow2'), digest


def download_image(url, digest, target):
    deadline = time.monotonic() + 600
    hasher = hashlib.sha512()
    total = 0
    created = False
    try:
        with urllib.request.urlopen(url, timeout=30) as response, target.open('xb') as output:
            created = True
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError('Debian cloud image download exceeded its budget')
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > 2 * 1024**3:
                    raise ValueError('Debian cloud image exceeds the size limit')
                hasher.update(block)
                output.write(block)
        if hasher.hexdigest() != digest:
            raise ValueError('Debian cloud image SHA512 mismatch; refusing to boot')
    except BaseException:
        if created:
            target.unlink(missing_ok=True)
        raise
    print('Verified dated Debian cloud image SHA512:', digest, flush=True)


def create_seed(work, identity):
    for name in ('client', 'host'):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'disposable-ci',
                        '-f', str(work / name)], check=True, timeout=10)
    config = {
        'users': [{'name': 'ci', 'shell': '/bin/bash', 'lock_passwd': True,
                   'sudo': 'ALL=(ALL) NOPASSWD:ALL',
                   'ssh_authorized_keys': [(work / 'client.pub').read_text().strip()]}],
        'disable_root': True, 'ssh_pwauth': False, 'ssh_deletekeys': True,
        'ssh_quiet_keygen': True, 'ssh': {'emit_keys_to_console': False},
        'ssh_publish_hostkeys': {'enabled': False},
        'ssh_keys': {'ed25519_private': (work / 'host').read_text(),
                     'ed25519_public': (work / 'host.pub').read_text().strip()},
        'write_files': [{'path': '/etc/proxyforge-vm-ci', 'permissions': '0600', 'content': identity}],
    }
    user_data = work / 'user-data'
    user_data.write_text('#cloud-config\n' + json.dumps(config), encoding='utf-8')
    user_data.chmod(0o600)
    (work / 'meta-data').write_text(json.dumps({'instance-id': identity, 'local-hostname': 'proxyforge-ci'}))
    subprocess.run(['cloud-localds', str(work / 'seed.img'), str(user_data), str(work / 'meta-data')],
                   check=True, timeout=30)
    (work / 'seed.img').chmod(0o600)


def qemu_command(work, arch, port):
    # Native architecture is required even when hardware virtualization is unavailable.
    kvm = os.access('/dev/kvm', os.R_OK | os.W_OK)
    accelerator = 'kvm' if kvm else 'tcg'
    command = ['qemu-system-x86_64' if arch == 'amd64' else 'qemu-system-aarch64',
               '-machine', 'q35' if arch == 'amd64' else 'virt', '-accel', accelerator,
               '-cpu', 'host' if kvm else ('qemu64' if arch == 'amd64' else 'max'),
               '-m', '2048', '-smp', '2', '-display', 'none', '-monitor', 'none',
               '-serial', 'file:' + str(work / 'serial.log'), '-no-reboot',
               '-drive', f'file={work / "guest.qcow2"},format=qcow2,if=virtio',
               '-drive', f'file={work / "seed.img"},format=raw,if=virtio,readonly=on',
               '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22',
               # Disk boot needs no optional iPXE network ROM.
               '-device', 'virtio-net-pci,netdev=net0,romfile=']
    if arch == 'arm64':
        command += ['-bios', '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd']
    print('Full Debian VM accelerator:', accelerator, 'native architecture:', arch, flush=True)
    return command


def verify_guest(evidence, version, arch, identity, host_kernel):
    native = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(evidence['machine'].lower())
    if (evidence['os'].get('ID'), evidence['os'].get('VERSION_ID'), native) != ('debian', version, arch):
        raise ValueError('Guest distribution/architecture does not match the VM matrix')
    if (evidence['marker'] != identity or evidence['pid1'] != 'systemd'
            or evidence['virtualization'] not in {'qemu', 'kvm'}
            or 'Debian' not in evidence['kernel_version'] or evidence['kernel'] == host_kernel):
        raise ValueError('Guest is not the newly created VM with an independent Debian kernel')
    print('Verified independent Debian VM:', version, arch, evidence['kernel'],
          evidence['virtualization'], flush=True)


def wait_cloud_init(ssh, vm):
    """Retry only the read-only wait when initial SSH service setup resets transport."""
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if vm.poll() is not None:
            raise RuntimeError('QEMU exited while waiting for cloud-init')
        try:
            result = subprocess.run([*ssh, 'sudo cloud-init status --wait'],
                                    capture_output=True, timeout=min(30, max(0.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            # The remote status command only observes cloud-init; no host mutation.
            pass
        else:
            if result.returncode == 0:
                print('Guest cloud-init completed', flush=True)
                return
            if result.returncode != 255:
                raise RuntimeError('Guest cloud-init failed with status ' + str(result.returncode))
            transient = (b'Connection reset', b'Connection closed', b'Connection refused',
                         b'Connection timed out', b'closed by remote host')
            if not any(message in result.stderr for message in transient):
                raise RuntimeError('Guest SSH wait failed; authentication and host key checks remain mandatory')
        time.sleep(min(5, max(0, deadline - time.monotonic())))
    raise TimeoutError('Guest cloud-init/SSH stabilization exceeded its budget')


PROBE = """import json,platform,subprocess
from pathlib import Path
print(json.dumps({'os': platform.freedesktop_os_release(), 'machine': platform.machine(),
 'kernel': platform.release(), 'kernel_version': Path('/proc/version').read_text(),
 'marker': Path('/etc/proxyforge-vm-ci').read_text(), 'pid1': Path('/proc/1/comm').read_text().strip(),
 'virtualization': subprocess.check_output(['systemd-detect-virt'],text=True).strip()}))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-system-test', action='store_true', required=True)
    parser.add_argument('--expected-debian', choices=('12', '13'), required=True)
    parser.add_argument('--expected-arch', choices=('amd64', 'arm64'), required=True)
    args = parser.parse_args()
    verify_host(args.expected_arch)
    subprocess.run(['python3', str(ROOT / 'scripts/check_repository_privacy.py')], check=True, timeout=30)
    identity = 'proxyforge-vm-ci-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='proxyforge-vm-ci-') as directory:
        work = Path(directory)
        work.chmod(0o700)
        url, digest = image_url(args.expected_debian, args.expected_arch)
        download_image(url, digest, work / 'base.qcow2')
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(work / 'base.qcow2'),
                        str(work / 'guest.qcow2'), '10G'], check=True, timeout=30)
        create_seed(work, identity)
        subprocess.run(['git', 'archive', '--format=tar.gz', '--output=' + str(work / 'source.tar.gz'), 'HEAD'],
                       cwd=ROOT, check=True, timeout=30)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        known_hosts = work / 'known_hosts'
        known_hosts.write_text(f'[127.0.0.1]:{port} ' + (work / 'host.pub').read_text())
        ssh = ['ssh', '-F', '/dev/null', '-p', str(port), '-i', str(work / 'client'),
               '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(known_hosts),
               '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'HostKeyAlgorithms=ssh-ed25519',
               '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3', 'ci@127.0.0.1']
        with (work / 'qemu.log').open('wb') as log:
            vm = subprocess.Popen(qemu_command(work, args.expected_arch, port), stdout=log, stderr=log,
                                  stdin=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 480
                while time.monotonic() < deadline:
                    if vm.poll() is not None:
                        raise RuntimeError('QEMU exited before SSH readiness')
                    ready = subprocess.run([*ssh, 'true'], capture_output=True, timeout=15)
                    if ready.returncode == 0:
                        break
                    time.sleep(5)
                else:
                    raise TimeoutError('Full Debian VM SSH readiness exceeded its budget')
                wait_cloud_init(ssh, vm)
                result = subprocess.check_output([*ssh, 'sudo /usr/bin/python3 -I -c ' + shlex.quote(PROBE)],
                                                 text=True, timeout=30)
                verify_guest(json.loads(result), args.expected_debian, args.expected_arch, identity, platform.release())
                subprocess.run([*ssh, 'mkdir -m 700 source && tar -xzf - -C source'],
                               input=(work / 'source.tar.gz').read_bytes(), check=True, timeout=90)
                setup = ('sudo env DEBIAN_FRONTEND=noninteractive apt-get update && '
                         'sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '
                         'python3-venv ca-certificates sudo && '
                         'sudo python3 -m venv /opt/controller-test && '
                         'sudo /opt/controller-test/bin/python -m pip --isolated install '
                         '--index-url https://pypi.org/simple --require-hashes --only-binary=:all: '
                         '-r source/requirements-dev.txt && sudo /opt/controller-test/bin/python -m pip check')
                subprocess.run([*ssh, setup], check=True, timeout=600)
                subprocess.run([*ssh, 'cd source && sudo env GITHUB_ACTIONS=true '
                                '/opt/controller-test/bin/python scripts/check_agent_installation.py '
                                '--disposable-system-test --check-helper --expected-debian ' + args.expected_debian
                                + ' --expected-arch ' + args.expected_arch], check=True, timeout=900)
                print('PASS: full native Debian VM/kernel, Agent HTTPS installation and explicit helper lifecycle', flush=True)
            except BaseException:
                log.flush()
                print((work / 'qemu.log').read_text(errors='replace')[-4096:], flush=True)
                serial = (work / 'serial.log').read_text(errors='replace') if (work / 'serial.log').exists() else ''
                # Only fixed booleans; never dump seed/user-data or guest journals.
                print('Guest boot markers:', json.dumps({
                    'kernel': 'Linux version' in serial, 'systemd': 'systemd' in serial,
                    'cloud_init': 'Cloud-init' in serial or 'cloud-init' in serial,
                    'emergency': 'emergency mode' in serial, 'kernel_panic': 'Kernel panic' in serial,
                }), flush=True)
                raise
            finally:
                # Reap only our own VM before deleting its private seed/keys/disks.
                vm.terminate()
                try:
                    vm.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait(timeout=10)


if __name__ == '__main__':
    main()
