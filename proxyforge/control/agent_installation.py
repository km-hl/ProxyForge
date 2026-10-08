"""Pure installation command contract shared by the console and documentation CLI."""
import ipaddress
import re
import shlex
import urllib.parse

BOOTSTRAP_COMMIT = "00d5a604499e5b22081bc280d4e1e3f0a69b650c"
BOOTSTRAP_SHA256 = "28fa9a875ef5c5513960cfbe8be269fe4a7bd688bb119a62bf461a3625df91c2"
SOURCE_COMMIT = "da2550a923f3a64a7d1e932a56090a34966f6ab7"


def controller_url(value):
    # Strict ASCII root URL, then pass it as one argument, never shell code.
    if not isinstance(value, str) or not value.isascii() or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise ValueError("Controller 地址必须是 HTTPS 根地址")
    try:
        url = urllib.parse.urlsplit(value)
        host, port = url.hostname, url.port
    except ValueError:
        raise ValueError("Controller 地址无效") from None
    if (url.scheme != "https" or not host or url.username is not None or url.password is not None
            or "?" in value or "#" in value or url.path not in ("", "/")
            or url.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535)):
        raise ValueError("Controller 地址必须是无凭据的 HTTPS 根地址")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or all(c in "0123456789." for c in host)
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ValueError("Controller 需要完整域名或公网 IP 地址")
    else:
        if not address.is_global:
            raise ValueError("Controller IP 地址必须是公网地址")
    return value.rstrip("/")



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



def installation_info(public_url):
    try:
        server = controller_url(public_url)
    except ValueError:
        return {"available": False, "message":
                "请部署管理员设置 PROXYFORGE_PUBLIC_URL 为有效的 HTTPS 根地址，再重建或重启 Controller。"}
    return {
        "available": True, "controller_url": server, "agent_version": "0.6.0",
        "bootstrap_commit": BOOTSTRAP_COMMIT, "bootstrap_sha256": BOOTSTRAP_SHA256,
        "source_commit": SOURCE_COMMIT,
        "commands": {
            mode: render(BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256, action=mode,
                         server=server if mode == "install" else None)
            for mode in ("install", "runtime", "check")
        },
    }
