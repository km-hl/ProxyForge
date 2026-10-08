"""从固定官方源码安装 Agent；完整命令及恢复说明见 docs/AGENT_INSTALL.md。"""

import argparse
import gzip
import hashlib
import io
import ipaddress
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request


# Fixed source including the helper UID capability fix; never a mutable branch.
SOURCE_COMMIT = "da2550a923f3a64a7d1e932a56090a34966f6ab7"
SOURCE_SHA256 = "3a95a0edac4ee87445feaffb10b053e6c4cee78e4b988dd5b1675768ac7b9a1c"
SOURCE_URL = "https://codeload.github.com/km-hl/ProxyForge/tar.gz/" + SOURCE_COMMIT
PREFIX = "ProxyForge-" + SOURCE_COMMIT
MAX_DOWNLOAD = 8 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_FILE = 1024 * 1024
FILES = frozenset((
    "__init__.py", "chain_spec.py", "client.py", "deployment_spec.py",
    "install-runtime.sh", "install.sh", "job_lease.py", "jobs.py",
    "landing_spec.py", "main.py", "proxyforge-agent.service",
    "proxyforge-runtime.service", "proxyforge-runtime.socket",
    "proxyforge-singbox.service", "README.md", "README.zh-CN.md",
    "runtime_client.py", "runtime_download.py", "runtime_engine.py",
    "runtime_helper.py", "runtime_spec.py", "singbox-release.json",
    "system_info.py", "install-compatibility.json",
))
INSTALLED_FILES = (
    "__init__.py", "main.py", "client.py", "system_info.py", "jobs.py",
    "job_lease.py", "runtime_spec.py", "deployment_spec.py", "landing_spec.py",
    "chain_spec.py", "runtime_download.py", "runtime_engine.py", "runtime_client.py",
    "singbox-release.json",
)
AGENT_TARGETS = ("/opt/proxyforge-agent", "/etc/proxyforge-agent",
                 "/etc/systemd/system/proxyforge-agent.service")
RUNTIME_TARGETS = ("/var/lib/proxyforge-runtime", "/run/proxyforge-runtime.sock",
                   "/etc/systemd/system/proxyforge-runtime.service",
                   "/etc/systemd/system/proxyforge-runtime.socket",
                   "/etc/systemd/system/proxyforge-singbox.service",
                   "/opt/proxyforge-agent/bin/sing-box")
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}


class InstallError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InstallError("下载发生重定向，已停止")


def controller_url(value):
    # Strict ASCII root URL, then pass it as one argument, never shell code.
    if not isinstance(value, str) or not value.isascii() or re.search(r"[\s\\\x00-\x1f\x7f]", value):
        raise InstallError("Controller 地址必须是 HTTPS 根地址")
    try:
        url = urllib.parse.urlsplit(value)
        host, port = url.hostname, url.port
    except ValueError:
        raise InstallError("Controller 地址无效") from None
    if (url.scheme != "https" or not host or url.username is not None or url.password is not None
            or "?" in value or "#" in value or url.path not in ("", "/")
            or url.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535)):
        raise InstallError("Controller 地址必须是无凭据的 HTTPS 根地址")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (len(host) > 253 or len(labels) < 2 or all(c in "0123456789." for c in host)
                or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise InstallError("Controller 需要完整域名或公网 IP 地址")
    else:
        if not address.is_global:
            raise InstallError("Controller IP 地址必须是公网地址")
    return value.rstrip("/")


def download():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 60
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "ProxyForge-Agent-Installer/1"})
    with opener.open(request, timeout=20) as response:
        if response.status != 200:
            raise InstallError("源码下载失败")
        data = bytearray()
        while len(data) <= MAX_DOWNLOAD:
            if time.monotonic() >= deadline:
                raise InstallError("源码下载超时")
            block = response.read1(min(65536, MAX_DOWNLOAD + 1 - len(data)))
            if not block:
                return bytes(data)
            data.extend(block)
    raise InstallError("源码包超过大小限制")


def verified_files(data):
    if len(data) > MAX_DOWNLOAD or hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise InstallError("源码包 SHA256 不匹配，未解包或执行")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    if len(expanded) > MAX_EXPANDED:
        raise InstallError("源码解压大小超过限制")
    selected, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            if (len(seen) >= 2048 or name in seen or "\\" in name or ":" in name
                    or any(part in ("", ".", "..") for part in parts) or parts[0] != PREFIX
                    or member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE)
                    or member.linkname or not 0 <= member.size <= MAX_FILE
                    or any(key != "comment" or value != SOURCE_COMMIT for key, value in member.pax_headers.items())):
                raise InstallError("源码归档成员不合法")
            seen.add(name)
            relative = PurePosixPath(*parts[1:])
            if len(parts) == 3 and parts[1] == "agent" and parts[2] in FILES:
                if not member.isfile():
                    raise InstallError("Agent 成员必须为普通文件")
                with archive.extractfile(member) as source:
                    selected[relative.name] = source.read(MAX_FILE + 1)
                if len(selected[relative.name]) != member.size:
                    raise InstallError("Agent 成员不完整")
    if set(selected) != FILES:
        raise InstallError("Agent 文件不完整")
    return selected


def trusted_directory(path):
    # Do not resolve symlinks before checking: all ancestors must be root-owned
    # real directories, with no group/other write permission (even sticky dirs).
    path = Path(path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError("安装目录及父目录必须由 root 控制且不可由其他用户写入")


def trusted_file(path):
    trusted_directory(path.parent)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or info.st_nlink != 1):
        raise InstallError("安装代码必须是 root 所有的独立普通文件")


def preflight(mode, server):
    if os.name != "posix" or os.geteuid() != 0 or platform.system() != "Linux":
        raise InstallError("安装需要 Linux root 权限")
    if sys.version_info < (3, 9):
        raise InstallError("需要 Python 3.9+")
    if mode == "install":
        controller_url(server)
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, _, value = line.partition("=")
        values[key] = value.strip('"')
    if ((values.get("ID"), values.get("VERSION_ID")) not in
            {("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04")}
            or platform.machine() not in {"x86_64", "aarch64"}):
        raise InstallError("不支持此发行版或架构")
    for path in ("/var/lib", "/opt", "/etc/systemd/system", "/run"):
        trusted_directory(path)
    if not Path("/run/systemd/system").is_dir():
        raise InstallError("需要正在运行的 systemd")
    targets = AGENT_TARGETS if mode == "install" else RUNTIME_TARGETS
    if any(os.path.lexists(path) for path in targets):
        raise InstallError("检测到已有安装或残留路径，请按中文恢复/升级流程处理")
    if mode == "install":
        # Do not silently adopt an existing account or a vendor/generated unit.
        import pwd
        try:
            pwd.getpwnam("proxyforge-agent")
        except KeyError:
            pass
        else:
            raise InstallError("Agent 用户已存在，请按恢复流程处理")
        result = subprocess.run(["/usr/bin/systemctl", "show", "--property=LoadState", "--value",
                                 "proxyforge-agent.service"], capture_output=True, timeout=10, env=SAFE_ENV)
        if result.returncode or result.stdout.strip() != b"not-found":
            raise InstallError("Agent unit 已存在或无法检查")
        # Terminals are not seekable; BufferedRandom (default rb+) rejects them.
        with open("/dev/tty", "rb+", buffering=0):
            pass
    elif not Path("/etc/proxyforge-agent/config.json").is_file():
        raise InstallError("请先完成普通 Agent 注册安装")


def check_installed_agent(files):
    directory = Path("/opt/proxyforge-agent/agent")
    trusted_directory(directory)
    for item in directory.rglob("*"):
        if item.is_dir():
            trusted_directory(item)
        else:
            trusted_file(item)
    for name in INSTALLED_FILES:
        path = directory / name
        trusted_file(path)
        if path.read_bytes() != files[name]:
            raise InstallError("已安装 Agent 与固定源码版本不同，请先按升级流程更新")


def install(mode, server=None):
    preflight(mode, server)
    print("正在下载并校验固定源码：" + SOURCE_COMMIT, flush=True)
    files = verified_files(download())
    if mode == "runtime":
        check_installed_agent(files)
    trusted_directory("/var/lib")
    stage = Path(tempfile.mkdtemp(prefix="proxyforge-agent-install-", dir="/var/lib"))
    try:
        trusted_directory(stage)
        package = stage / "agent"
        package.mkdir(mode=0o755)
        # Write only validated in-memory bytes, never tar.extract/all or a path
        # re-read from a user-controlled download directory.
        for name, data in files.items():
            target = package / name
            with target.open("xb") as output:
                output.write(data)
            target.chmod(0o644)
            trusted_file(target)
        preflight(mode, server)
        if mode == "runtime":
            check_installed_agent(files)
        script = package / ("install.sh" if mode == "install" else "install-runtime.sh")
        args = ["/bin/bash", "-p", str(script)]
        if mode == "install":
            args.append(controller_url(server))
        subprocess.run(args, cwd=stage, env=SAFE_ENV, check=True)
    finally:
        # A fresh root-only temporary directory; never an installed/config path.
        shutil.rmtree(stage)
    print("本机安装脚本已完成；请在控制台核对心跳或能力状态。")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "runtime", "check"),
                        help="install 普通 Agent；runtime 显式启用 helper；check 只下载校验")
    parser.add_argument("--server", help="可信 Controller HTTPS 根地址，仅 install 使用")
    args = parser.parse_args()
    try:
        if args.action == "install" and not args.server:
            raise InstallError("install 必须指定 --server")
        if args.action != "install" and args.server is not None:
            raise InstallError("仅 install 接受 --server")
        if not sys.flags.isolated:
            raise InstallError("请使用 python3 -I 隔离模式运行")
        if args.action == "check":
            files = verified_files(download())
            print("源码校验通过，Agent 文件数：", len(files))
        else:
            install(args.action, args.server)
    except InstallError as error:
        parser.exit(1, str(error) + "；请按 docs/AGENT_INSTALL.md 排查。\n")
    except (OSError, ValueError, EOFError, tarfile.TarError, subprocess.SubprocessError):
        # Never print arbitrary network responses, URLs, credentials or paths.
        parser.exit(1, "安装准备或执行失败；未自动重试注册。请按 docs/AGENT_INSTALL.md 排查。\n")


if __name__ == "__main__":
    main()
