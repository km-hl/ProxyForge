"""生成固定 bootstrap 及 SHA256 的中文文档安装命令，不包含注册凭据。"""

import argparse

from proxyforge.control.agent_installation import render


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap-commit", required=True)
    parser.add_argument("--bootstrap-sha256", dest="digest", required=True)
    parser.add_argument("--action", choices=("install", "runtime", "check"), default="install")
    parser.add_argument("--server")
    args = parser.parse_args()
    print(render(args.bootstrap_commit, args.digest, action=args.action, server=args.server), end="")


if __name__ == "__main__":
    main()
