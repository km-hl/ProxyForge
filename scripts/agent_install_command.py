"""生成固定 bootstrap 及 SHA256 的中文文档安装命令，不包含注册凭据。"""

import argparse
import re
import shlex

from scripts.agent_bootstrap import controller_url


def render(commit, digest, *, action="install", server=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("需要完整 bootstrap 提交及 SHA256")
    if action not in ("install", "runtime", "check"):
        raise ValueError("不支持的安装操作")
    args = [action]
    if action == "install":
        args.extend(["--server", controller_url(server)])
    elif server is not None:
        raise ValueError("仅普通安装使用 Controller 地址")
    # This trusted command is the bootstrap's trust anchor. Read bounded bytes
    # into memory and verify before executing; no user-writable script path.
    invocation = "sudo /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 /usr/bin/python3 -I - "
    if action == "check":
        invocation = "/usr/bin/python3 -I - "
    return invocation + shlex.join(args) + " <<'PROXYFORGE_BOOTSTRAP'\n" + f'''import hashlib
import sys
import urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SystemExit("Bootstrap redirect rejected")
url = "https://raw.githubusercontent.com/km-hl/ProxyForge/{commit}/scripts/agent_bootstrap.py"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), NoRedirect())
try:
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise SystemExit("Bootstrap download failed")
        code = response.read(65537)
except OSError:
    raise SystemExit("Bootstrap download failed") from None
if len(code) > 65536 or hashlib.sha256(code).hexdigest() != "{digest}":
    raise SystemExit("Bootstrap SHA256 mismatch; nothing executed")
sys.argv = ["verified-agent-bootstrap"] + sys.argv[1:]
exec(compile(code, "<verified-agent-bootstrap>", "exec"), {{"__name__": "__main__"}})
PROXYFORGE_BOOTSTRAP
'''


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
