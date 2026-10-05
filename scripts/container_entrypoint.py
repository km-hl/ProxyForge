"""以固定非 root 身份检查数据目录后启动 Controller。"""
import os
import sys

from container_data import UID, GID, GUIDANCE, inspect_data


def main():
    if os.geteuid() != UID or os.getegid() != GID:
        raise SystemExit('Controller 必须以 10001:10001 运行；迁移请使用文档中的一次性命令。')
    os.umask(0o077)
    try:
        inspect_data(runtime=True)
    except (OSError, ValueError):
        raise SystemExit(GUIDANCE) from None
    if len(sys.argv) < 2:
        raise SystemExit('缺少 Controller 启动命令')
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
