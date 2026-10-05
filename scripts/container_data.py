"""容器数据目录检查/停机迁移；仅操作 /app/data，见 docs/CONTAINER_PERMISSIONS.md。"""
import argparse
import os
from pathlib import Path
import stat


DATA = Path('/app/data')
UID = GID = 10001
GUIDANCE = ('数据目录权限检查失败。请停止所有 Controller 写入者、备份完整 data，'
            '再按 docs/CONTAINER_PERMISSIONS.md 执行检查和迁移；不要以 root 启动服务。')


def visit(root_fd, device, action):
    """Use directory descriptors and never follow links, including during mutation."""
    info = os.fstat(root_fd)
    if info.st_dev != device:
        raise ValueError('不支持数据目录内的跨文件系统挂载')
    action(root_fd, info, True)
    for name in os.listdir(root_fd):
        info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        directory = stat.S_ISDIR(info.st_mode)
        if not directory and not stat.S_ISREG(info.st_mode):
            raise ValueError('数据目录包含符号链接或特殊文件')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(name, flags, dir_fd=root_fd)
        try:
            current = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError('目录在检查期间发生变化，请停止所有写入者')
            if directory:
                visit(fd, device, action)
            else:
                if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
                    raise ValueError('数据目录包含硬链接或特殊文件')
                if current.st_dev != device:
                    raise ValueError('不支持数据目录内的跨文件系统挂载')
                action(fd, current, False)
        finally:
            os.close(fd)


def check_mode(fd, info, directory):
    needed = 0o700 if directory else 0o600
    if stat.S_IMODE(info.st_mode) & needed != needed:
        raise ValueError('文件所有者缺少读写权限，或目录缺少遍历权限；请人工核对只读文件')


def check_owner(fd, info, directory):
    check_mode(fd, info, directory)
    if info.st_uid != UID or info.st_gid != GID:
        raise ValueError('数据所有权需要迁移到 10001:10001')
    if stat.S_IMODE(info.st_mode) & ~ (0o700 if directory else 0o600):
        raise ValueError('数据权限过宽，需要停机迁移收紧权限')


def inspect_data(apply=False, runtime=False):
    fd = os.open(DATA, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        device = os.fstat(fd).st_dev
        # Validate the entire tree before the first ownership/mode change.
        visit(fd, device, check_owner if runtime else check_mode)
        if apply:
            def change(item_fd, info, directory):
                check_mode(item_fd, info, directory)
                os.fchown(item_fd, UID, GID)
                os.fchmod(item_fd, 0o700 if directory else 0o600)
            visit(fd, device, change)
        if runtime:
            # Test actual create/write/rename/delete access, including read-only mounts.
            import secrets
            first = '.permission-check-' + secrets.token_hex(12)
            second = first + '-renamed'
            probe = os.open(first, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                            0o600, dir_fd=fd)
            try:
                os.write(probe, b'check')
                os.fsync(probe)
                os.rename(first, second, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                os.close(probe)
                for name in (first, second):
                    try:
                        os.unlink(name, dir_fd=fd)
                    except FileNotFoundError:
                        pass
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='停机并备份后应用所有权/私有权限迁移')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('迁移工具须作为显式的一次性 root 容器运行')
    try:
        inspect_data(apply=args.apply)
    except (OSError, ValueError) as exc:
        raise SystemExit(GUIDANCE + '\n检查未完成；迁移可能部分完成，可修复后重新运行。'
                         + ('\n' + str(exc) if isinstance(exc, ValueError) else '')) from None
    print('迁移完成：10001:10001，目录0700/文件0600。' if args.apply
          else '检查通过；未修改数据。确认已停机并备份后，可使用 --apply。')


if __name__ == '__main__':
    main()
