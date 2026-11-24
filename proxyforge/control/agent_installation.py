"""Pure installation command contract & quick verified bundle shared by console and CLI."""
import functools
import gzip
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import shlex
import tarfile
from typing import Optional
import urllib.parse

BOOTSTRAP_COMMIT = "500b025e48a8b4a7f01c53ebc640145bcad916db"
BOOTSTRAP_SHA256 = "dcbc31342fec1b372c6735e92613395b94cba089f83eab9c6b2fdd98631acd68"
SOURCE_COMMIT = "9738da476fbc3bf6702d335a9b7424192902add5"

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_BUNDLE_FILE = 1024 * 1024
AGENT_BUNDLE_FILES = (
    "__init__.py",
    "acme_manager.py",
    "adoption.py",
    "caddy-release.json",
    "caddy_manager.py",
    "chain_spec.py",
    "client.py",
    "deployment_spec.py",
    "gost-release.json",
    "gost_manager.py",
    "install-compatibility.json",
    "install-runtime.sh",
    "install.sh",
    "job_lease.py",
    "jobs.py",
    "landing_spec.py",
    "main.py",
    "nft_users.py",
    "proxyforge-agent.service",
    "proxyforge-caddy.service",
    "proxyforge-gost.service",
    "proxyforge-runtime.service",
    "proxyforge-runtime.socket",
    "proxyforge-singbox.service",
    "README.md",
    "README.zh-CN.md",
    "runtime_client.py",
    "runtime_download.py",
    "runtime_engine.py",
    "runtime_helper.py",
    "runtime_spec.py",
    "self_upgrade.py",
    "singbox-release.json",
    "system_info.py",
    "traffic_collector.py",
    "LICENSE",
)
_LF_SUFFIXES = (".sh", ".service", ".socket")


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


def release_versions(repo_root: Optional[Path] = None) -> dict:
    root = Path(repo_root) if repo_root else REPO_ROOT
    agent_dir = root / "agent"
    versions = {}
    for key, filename in (("singbox", "singbox-release.json"), ("caddy", "caddy-release.json"), ("gost", "gost-release.json")):
        path = agent_dir / filename
        if path.is_file():
            versions[key] = json.loads(path.read_text(encoding="utf-8")).get("version", "")
    return versions


@functools.lru_cache(maxsize=4)
def _cached_agent_bundle(root_str: str) -> tuple:
    root = Path(root_str)
    agent_dir = root / "agent"
    entries = []
    root_license = root / "LICENSE"
    if root_license.is_file():
        entries.append(("LICENSE", root_license.read_bytes(), 0o644))
    for name in sorted(AGENT_BUNDLE_FILES):
        src = agent_dir / name
        if not src.is_file():
            raise FileNotFoundError(f"Missing required Agent bundle file: agent/{name}")
        raw = src.read_bytes()
        if len(raw) > MAX_BUNDLE_FILE:
            raise ValueError(f"Agent bundle member exceeds limit: agent/{name}")
        if name.endswith(_LF_SUFFIXES):
            raw = raw.replace(b"\r\n", b"\n")
        mode = 0o755 if name.endswith(".sh") else 0o644
        entries.append((f"agent/{name}", raw, mode))

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for arcname, raw, mode in entries:
            info = tarfile.TarInfo(arcname)
            info.size = len(raw)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(raw))

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_buf.getvalue())
    payload = gz_buf.getvalue()
    return payload, hashlib.sha256(payload).hexdigest()


def build_agent_bundle(repo_root: Optional[Path] = None) -> tuple:
    """Build deterministic gzip tarball + SHA256 containing only public agent/ code and LICENSE."""
    root = (Path(repo_root) if repo_root else REPO_ROOT).resolve()
    return _cached_agent_bundle(str(root))


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


_QUICK_INSTALL_TEMPLATE = r'''#!/usr/bin/env bash
set -euo pipefail

DEFAULT_SERVER=__DEFAULT_SERVER__
BUNDLE_SHA256=__BUNDLE_SHA256__
SERVER="$DEFAULT_SERVER"
REG_TOKEN=""
ENABLE_RUNTIME=0
WITH_SINGBOX=0
WITH_CADDY=0
WITH_GOST=0
ADOPT_SCAN=0
UPGRADE=0
REINSTALL=0
ALLOW_INSECURE=0
CA_FILE=""
GH_PROXY=""
INSTALL_DEPS=1

usage() {
    cat <<'EOF'
ProxyForge Agent 一键安装 / 升级脚本 (Debian 12/13, Ubuntu 22.04/24.04)

用法:
  bash <(curl -fsSL https://controller.example/api/agent/install.sh) [选项]

可选项:
  -e, --server URL      Controller HTTPS 根地址 (默认: 脚本内置地址)
  -t, --token TOKEN     一次性注册凭据 (不传则从交互终端隐藏输入)
      --runtime         同时启用本机托管 Runtime (sing-box / Caddy / go-gost 必选)
      --with-singbox    预装并激活固定版本 sing-box (自动启用 --runtime)
      --with-caddy      预装并激活固定版本 Caddy (自动启用 --runtime)
      --with-gost       预装并激活固定版本 go-gost (自动启用 --runtime)
      --with-all        等价于 --runtime --with-singbox --with-caddy --with-gost
      --adopt-scan      安装完成后立即扫描本机存量 sing-box / xray / caddy 节点
      --upgrade         升级 Agent / Runtime 代码并保留原有配置与密钥
      --reinstall       清除原有 ProxyForge Agent / Runtime 安装后全新重装
  -k, --insecure        跳过 Controller TLS 证书校验 (自签证书/反代场景)
      --ca-file PATH    指定自定义 CA 证书路径
      --gh-proxy URL    下载 GitHub 发布二进制时使用的 https:// 镜像前缀
      --no-deps         跳过缺失 python3 / ca-certificates 的 apt 自动安装
  -h, --help            显示此帮助信息
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -e|--server) SERVER="${2:?缺少 --server 参数}"; shift 2 ;;
        -t|--token) REG_TOKEN="${2:?缺少 --token 参数}"; shift 2 ;;
        --runtime) ENABLE_RUNTIME=1; shift ;;
        --with-singbox) ENABLE_RUNTIME=1; WITH_SINGBOX=1; shift ;;
        --with-caddy) ENABLE_RUNTIME=1; WITH_CADDY=1; shift ;;
        --with-gost) ENABLE_RUNTIME=1; WITH_GOST=1; shift ;;
        --with-all) ENABLE_RUNTIME=1; WITH_SINGBOX=1; WITH_CADDY=1; WITH_GOST=1; shift ;;
        --adopt-scan) ADOPT_SCAN=1; shift ;;
        --upgrade) UPGRADE=1; shift ;;
        --reinstall) REINSTALL=1; shift ;;
        -k|--insecure) ALLOW_INSECURE=1; shift ;;
        --ca-file) CA_FILE="${2:?缺少 --ca-file 参数}"; shift 2 ;;
        --gh-proxy) GH_PROXY="${2:?缺少 --gh-proxy 参数}"; shift 2 ;;
        --no-deps) INSTALL_DEPS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ $UPGRADE -eq 1 && $REINSTALL -eq 1 ]]; then
    echo "错误: --upgrade 与 --reinstall 不能同时使用" >&2
    exit 1
fi
if [[ $EUID -ne 0 ]]; then
    echo "错误: 请使用 root 账户执行，或在命令前加 sudo (例如: curl -fsSL ... | sudo bash -s -- ...)" >&2
    exit 1
fi
if [[ -z "$SERVER" ]]; then
    echo "错误: 请通过 -e https://your-controller.example 指定 Controller 地址" >&2
    exit 1
fi
if [[ ! -d /run/systemd/system || ! -x /usr/bin/systemctl ]]; then
    echo "错误: 需要正在运行的 systemd 环境" >&2
    exit 1
fi

if [[ $INSTALL_DEPS -eq 1 ]]; then
    missing_pkgs=()
    [[ -x /usr/bin/python3 ]] || missing_pkgs+=(python3)
    [[ -f /etc/ssl/certs/ca-certificates.crt ]] || missing_pkgs+=(ca-certificates)
    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "正在安装缺失基础依赖: ${missing_pkgs[*]} ..."
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing_pkgs[@]}"
        else
            echo "错误: 缺少系统依赖 (${missing_pkgs[*]})，且未检测到 apt-get" >&2
            exit 1
        fi
    fi
fi

[[ -x /usr/bin/python3 ]] || { echo "错误: 需要 /usr/bin/python3 (3.9+)" >&2; exit 1; }

STAGE=""
cleanup() {
    unset REG_TOKEN || true
    if [[ -n "$STAGE" && -d "$STAGE" ]]; then
        rm -rf -- "$STAGE"
    fi
}
trap cleanup EXIT

mkdir -p /var/lib
chmod 0755 /var/lib
STAGE=$(mktemp -d /var/lib/proxyforge-install-XXXXXX)
chmod 0700 "$STAGE"

echo "正在从 Controller 下载并校验 Agent 运行包..."
/usr/bin/python3 -I - "$SERVER" "$BUNDLE_SHA256" "$STAGE" "$ALLOW_INSECURE" "$CA_FILE" <<'PY'
import gzip, hashlib, io, platform, re, ssl, sys, tarfile, urllib.parse, urllib.request
from pathlib import Path

server, expected_sha, stage, insecure_raw, ca_file = sys.argv[1:6]
allow_insecure = insecure_raw == "1"

if not isinstance(server, str) or not server.isascii() or re.search(r"[\s\\\x00-\x1f\x7f]", server):
    raise SystemExit("无效的 Controller 地址")
parsed = urllib.parse.urlsplit(server)
if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
        or "?" in server or "#" in server or parsed.path not in ("", "/") or parsed.netloc.endswith(":")):
    raise SystemExit("Controller 必须是无凭据的 HTTPS 根地址")
server = server.rstrip("/")

values = {}
for line in Path("/etc/os-release").read_text().splitlines():
    k, _, v = line.partition("=")
    values[k] = v.strip('"')
if (values.get("ID"), values.get("VERSION_ID")) not in {
    ("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04")
} or platform.machine() not in {"x86_64", "aarch64"}:
    raise SystemExit("当前系统不在支持列表 (Debian 12/13, Ubuntu 22.04/24.04 x86_64/arm64)")
if sys.version_info < (3, 9):
    raise SystemExit("需要 Python 3.9+")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SystemExit("下载发生未授权重定向，已停止")

ctx = ssl.create_default_context(cafile=ca_file or None)
if allow_insecure and not ca_file:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
req = urllib.request.Request(server + "/api/agent/package.tar.gz", headers={"User-Agent": "ProxyForge-QuickInstall/1"})
with opener.open(req, timeout=25) as resp:
    if resp.status != 200:
        raise SystemExit(f"下载失败: HTTP {resp.status}")
    data = resp.read(8 * 1024 * 1024 + 1)

if len(data) > 8 * 1024 * 1024:
    raise SystemExit("安装包超过大小限制")
if hashlib.sha256(data).hexdigest() != expected_sha:
    raise SystemExit("安装包 SHA256 校验失败，已中止执行")

with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
    raw_tar = gz.read(32 * 1024 * 1024 + 1)
if len(raw_tar) > 32 * 1024 * 1024:
    raise SystemExit("解压后内容超过大小限制")

stage_root = Path(stage).resolve()
with tarfile.open(fileobj=io.BytesIO(raw_tar), mode="r:") as arc:
    for member in arc:
        parts = member.name.split("/")
        if ("\\" in member.name or ":" in member.name or any(p in ("", ".", "..") for p in parts)
                or member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE) or member.linkname):
            raise SystemExit(f"归档成员路径不安全: {member.name}")
        if not (parts == ["LICENSE"] or (len(parts) == 2 and parts[0] == "agent")):
            raise SystemExit(f"意外的归档成员: {member.name}")
        if not member.isfile():
            continue
        dest = (stage_root / member.name).resolve()
        if dest.parent != stage_root and dest.parent != stage_root / "agent":
            raise SystemExit("归档目标越界")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with arc.extractfile(member) as src, dest.open("wb") as out:
            out.write(src.read(1024 * 1024 + 1))
        dest.chmod(0o755 if member.name.endswith(".sh") else 0o644)
PY
SERVER="${SERVER%/}"

stop_existing_units() {
    for unit in proxyforge-agent.service proxyforge-runtime.socket proxyforge-runtime.service \
                proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service; do
        systemctl stop "$unit" >/dev/null 2>&1 || true
    done
}

if [[ $REINSTALL -eq 1 ]]; then
    echo "正在清理旧版 ProxyForge Agent / Runtime 安装..."
    stop_existing_units
    for unit in proxyforge-agent.service proxyforge-runtime.socket proxyforge-runtime.service \
                proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service; do
        systemctl disable "$unit" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/$unit"
    done
    rm -rf /opt/proxyforge-agent /etc/proxyforge-agent /var/lib/proxyforge-runtime /run/proxyforge-runtime.sock
    for acct in proxyforge-agent proxyforge-singbox proxyforge-caddy proxyforge-gost; do
        if id "$acct" >/dev/null 2>&1; then
            userdel "$acct" >/dev/null 2>&1 || true
        fi
    done
    systemctl daemon-reload
fi

if [[ $UPGRADE -eq 1 ]]; then
    [[ -f /etc/proxyforge-agent/config.json ]] || { echo "错误: 未找到 /etc/proxyforge-agent/config.json，请去掉 --upgrade 执行全新安装" >&2; exit 1; }
    echo "正在原地升级 Agent 代码并保留原有配置与密钥..."
    systemctl stop proxyforge-agent.service >/dev/null 2>&1 || true
    install -d -m 0755 /opt/proxyforge-agent/agent
    for file in "$STAGE"/agent/*.py "$STAGE"/agent/*.json "$STAGE/agent/LICENSE"; do
        [[ -f "$file" ]] && install -m 0644 "$file" "/opt/proxyforge-agent/agent/$(basename "$file")"
    done
    install -m 0644 "$STAGE/agent/proxyforge-agent.service" /etc/systemd/system/proxyforge-agent.service

    runtime_was_installed=0
    if [[ -d /var/lib/proxyforge-runtime || -f /etc/systemd/system/proxyforge-runtime.socket ]]; then
        runtime_was_installed=1
    fi
    if [[ $runtime_was_installed -eq 1 ]]; then
        systemctl stop proxyforge-runtime.socket proxyforge-runtime.service >/dev/null 2>&1 || true
        for acct in proxyforge-singbox proxyforge-caddy proxyforge-gost; do
            id "$acct" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$acct"
        done
        install -d -m 0755 /var/lib/proxyforge-runtime /var/lib/proxyforge-runtime/releases \
            /var/lib/proxyforge-runtime/services /var/lib/proxyforge-runtime/services/caddy \
            /var/lib/proxyforge-runtime/services/caddy/releases \
            /var/lib/proxyforge-runtime/services/gost /var/lib/proxyforge-runtime/services/gost/releases \
            /opt/proxyforge-agent/bin
        install -d -m 0700 -o proxyforge-caddy -g proxyforge-caddy /var/lib/proxyforge-runtime/services/caddy/state
        install -d -m 0700 -o proxyforge-gost -g proxyforge-gost /var/lib/proxyforge-runtime/services/gost/state
        ln -sfn /var/lib/proxyforge-runtime/current/sing-box /opt/proxyforge-agent/bin/sing-box
        ln -sfn /var/lib/proxyforge-runtime/services/caddy/current/caddy /opt/proxyforge-agent/bin/caddy
        ln -sfn /var/lib/proxyforge-runtime/services/gost/current/gost /opt/proxyforge-agent/bin/gost
        for unit in proxyforge-runtime.socket proxyforge-runtime.service proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service; do
            install -m 0644 "$STAGE/agent/$unit" "/etc/systemd/system/$unit"
        done
        for marker in deployment-protocol landing-protocol chain-protocol gost-protocol self-upgrade-protocol; do
            printf '1\n' > "/opt/proxyforge-agent/$marker"
            chmod 0644 "/opt/proxyforge-agent/$marker"
        done
        systemctl daemon-reload
        systemctl enable proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service >/dev/null 2>&1 || true
        systemctl enable --now proxyforge-runtime.socket
        if systemctl is-active --quiet proxyforge-singbox.service; then
            systemctl restart proxyforge-singbox.service >/dev/null 2>&1 || true
        fi
    elif [[ $ENABLE_RUNTIME -eq 1 ]]; then
        systemctl daemon-reload
        bash "$STAGE/agent/install-runtime.sh"
    else
        systemctl daemon-reload
    fi
    if [[ -n "$BUNDLE_SHA256" ]]; then
        printf '%s\n' "$BUNDLE_SHA256" > /opt/proxyforge-agent/bundle-sha256
        chmod 0644 /opt/proxyforge-agent/bundle-sha256
    fi
    systemctl enable --now proxyforge-agent.service
    systemctl restart proxyforge-agent.service
else
    install_args=()
    if [[ -n "$REG_TOKEN" ]]; then
        token_tmp="$STAGE/.reg_token"
        install -m 0600 /dev/null "$token_tmp"
        printf '%s\n' "$REG_TOKEN" > "$token_tmp"
        unset REG_TOKEN
        install_args+=(--token-file "$token_tmp")
    fi
    if [[ $ALLOW_INSECURE -eq 1 ]]; then
        install_args+=(--allow-insecure)
    fi
    if [[ -n "$CA_FILE" ]]; then
        install_args+=(--ca-file "$CA_FILE")
    fi
    bash "$STAGE/agent/install.sh" ${install_args[@]+"${install_args[@]}"} "$SERVER"
    if [[ -n "$BUNDLE_SHA256" ]]; then
        printf '%s\n' "$BUNDLE_SHA256" > /opt/proxyforge-agent/bundle-sha256
        chmod 0644 /opt/proxyforge-agent/bundle-sha256
    fi
    if [[ $ENABLE_RUNTIME -eq 1 ]]; then
        echo "正在启用托管 Runtime 辅助服务 (sing-box / Caddy / go-gost)..."
        bash "$STAGE/agent/install-runtime.sh"
        systemctl restart proxyforge-agent.service
    fi
fi

if [[ -n "$GH_PROXY" && -d /var/lib/proxyforge-runtime ]]; then
    echo "正在持久化 GitHub 加速镜像配置，供后续内核下载任务自动使用..."
    /usr/bin/python3 -I - "$GH_PROXY" <<'PY'
import os, sys
from pathlib import Path
sys.path.insert(0, "/opt/proxyforge-agent")
from agent.runtime_download import MIRROR_CONFIG_FILENAME, normalize_mirror_prefix
mirror = normalize_mirror_prefix(sys.argv[1])
if mirror:
    dest = Path("/var/lib/proxyforge-runtime") / MIRROR_CONFIG_FILENAME
    dest.write_text(mirror + "\n", encoding="utf-8")
    os.chown(dest, 0, 0)
    dest.chmod(0o644)
    print(f"已保存 GitHub 镜像前缀: {mirror}")
PY
fi

if [[ $WITH_SINGBOX -eq 1 || $WITH_CADDY -eq 1 || $WITH_GOST -eq 1 ]]; then
    echo "正在预装所选内核组件..."
    /usr/bin/python3 -I - "$WITH_SINGBOX" "$WITH_CADDY" "$WITH_GOST" "$GH_PROXY" <<'PY'
import platform, sys, uuid
from pathlib import Path
sys.path.insert(0, "/opt/proxyforge-agent")
from agent.runtime_download import download_binary, download_caddy_binary, download_gost_binary
from agent.runtime_helper import build_coordinator
from agent.runtime_spec import CADDY_RELEASE, GOST_RELEASE, MANAGED_SERVICES, RELEASE, revision

w_sb, w_cd, w_gs, gh_proxy = sys.argv[1:5]
arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
if not arch:
    raise SystemExit("Unsupported architecture")
mirror = gh_proxy or None
downloaders = {
    "sing-box": (lambda d, a, g=lambda: None: download_binary(d, a, g, mirror_prefix=mirror)),
    "caddy": (lambda d, a, g=lambda: None: download_caddy_binary(d, a, g, mirror_prefix=mirror)),
    "go-gost": (lambda d, a, g=lambda: None: download_gost_binary(d, a, g, mirror_prefix=mirror)),
}
coord = build_coordinator(Path("/var/lib/proxyforge-runtime"), arch, downloaders=downloaders, services=MANAGED_SERVICES)
tasks = []
if w_sb == "1":
    tasks.append(("singbox.install", RELEASE["version"]))
if w_cd == "1":
    tasks.append(("caddy.install", CADDY_RELEASE["version"]))
if w_gs == "1":
    tasks.append(("gost.install", GOST_RELEASE["version"]))
for action, ver in tasks:
    jid = uuid.uuid4().hex
    payload = {"version": ver}
    job = {"id": jid, "type": action, "payload": payload, "deployment_revision": revision(jid, action, payload)}
    res = coord.apply(job)
    print(f"已安装 {action} -> version={res.get('version', ver)} status={res.get('status')}")
PY
fi

if [[ $ADOPT_SCAN -eq 1 ]]; then
    echo "正在执行初始存量节点接管扫描..."
    (cd /opt/proxyforge-agent && runuser -u proxyforge-agent -- /usr/bin/python3 -m agent.main --config /etc/proxyforge-agent/config.json adopt-scan) || echo "警告: 初始接管扫描未完成，可稍后手动重试"
fi

echo ""
echo "ProxyForge Agent 安装/配置完成！"
echo "  查看运行状态: systemctl status proxyforge-agent.service --no-pager"
echo "  查看实时日志: journalctl -u proxyforge-agent.service -n 30 --no-pager"
'''


def render_quick_install_script(default_server=None, *, bundle_sha256: str) -> str:
    """Render single-command Komari-style installer pinned to the running Controller bundle SHA256."""
    if not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256):
        raise ValueError("需要完整的 SHA256 校验值")
    safe_default = controller_url(default_server) if default_server else ""
    return (
        _QUICK_INSTALL_TEMPLATE
        .replace("__DEFAULT_SERVER__", shlex.quote(safe_default))
        .replace("__BUNDLE_SHA256__", shlex.quote(bundle_sha256))
        .replace("\r\n", "\n")
    )


def installation_info(public_url):
    versions = release_versions()
    try:
        server = controller_url(public_url)
    except ValueError:
        return {
            "available": False,
            "release_versions": versions,
            "message": "请部署管理员设置 PROXYFORGE_PUBLIC_URL 为有效的 HTTPS 根地址，再重建或重启 Controller。",
        }
    _, bundle_sha256 = build_agent_bundle()
    return {
        "available": True,
        "controller_url": server,
        "agent_version": "0.6.0",
        "bootstrap_commit": BOOTSTRAP_COMMIT,
        "bootstrap_sha256": BOOTSTRAP_SHA256,
        "source_commit": SOURCE_COMMIT,
        "quick_install_url": f"{server}/api/agent/install.sh",
        "package_url": f"{server}/api/agent/package.tar.gz",
        "package_sha256": bundle_sha256,
        "release_versions": versions,
        "commands": {
            mode: render(BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256, action=mode,
                         server=server if mode == "install" else None)
            for mode in ("install", "runtime", "check")
        },
    }
