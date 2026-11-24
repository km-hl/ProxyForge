"""Read-only inventory; no user-controlled command arguments."""
import hashlib
import ipaddress
import platform
from pathlib import Path
import socket
import subprocess
import time

from . import VERSION, PROTOCOL_VERSION
from .runtime_client import available as runtime_available
from .runtime_client import (
    chain_available,
    deployment_available,
    gost_available,
    landing_available,
    self_upgrade_available,
)
from .self_upgrade import read_installed_bundle_sha256

SUPPORTED = {("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04")}
_PUBLIC_IP_CACHE = {"at": 0.0, "ipv4": "", "ipv6": ""}
_PUBLIC_IP_TTL = 600.0


def _local_route_global_ips():
    """Zero-packet kernel route table lookup for global unicast IPv4/IPv6 interface addresses."""
    found = {"ipv4": "", "ipv6": ""}
    probes = (
        ("ipv4", socket.AF_INET, "223.5.5.5", 4),
        ("ipv6", socket.AF_INET6, "2606:4700:4700::1111", 6),
    )
    for key, family, target, version in probes:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 80))
                raw = sock.getsockname()[0].split("%", 1)[0]
            ip = ipaddress.ip_address(raw)
            if ip.is_global and ip.version == version:
                found[key] = str(ip)
        except (OSError, ValueError):
            continue
    return found


def detect_public_addresses(*, allow_network=False, ip_reader=None, now_fn=time.monotonic):
    """Detect host public IPv4 and IPv6 addresses without blocking heartbeats."""
    local_ips = _local_route_global_ips()
    ipv4 = local_ips["ipv4"]
    ipv6 = local_ips["ipv6"]
    if allow_network and (not ipv4 or not ipv6):
        now = float(now_fn())
        if now - _PUBLIC_IP_CACHE["at"] >= _PUBLIC_IP_TTL or (not _PUBLIC_IP_CACHE["ipv4"] and not _PUBLIC_IP_CACHE["ipv6"]):
            if ip_reader is None:
                from .acme_manager import public_ips as ip_reader
            try:
                probed = ip_reader() or {}
            except Exception:
                probed = {}
            _PUBLIC_IP_CACHE["at"] = now
            _PUBLIC_IP_CACHE["ipv4"] = str(probed.get("ipv4") or "")
            _PUBLIC_IP_CACHE["ipv6"] = str(probed.get("ipv6") or "")
        if not ipv4 and _PUBLIC_IP_CACHE["ipv4"]:
            ipv4 = _PUBLIC_IP_CACHE["ipv4"]
        if not ipv6 and _PUBLIC_IP_CACHE["ipv6"]:
            ipv6 = _PUBLIC_IP_CACHE["ipv6"]
    result = []
    for candidate in (ipv4, ipv6):
        if candidate:
            try:
                ip = ipaddress.ip_address(candidate)
                if ip.is_global and str(ip) not in result:
                    result.append(str(ip))
            except ValueError:
                continue
    return result


def os_release(path=Path("/etc/os-release")):
    values = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key in {"ID", "VERSION_ID"}:
                values[key] = value.strip('"')
    except OSError:
        pass
    return values.get("ID", platform.system().lower()), values.get("VERSION_ID", "")


def singbox_status():
    # Only the independent future ProxyForge runtime is reported. Never invoke
    # an arbitrary PATH executable or inspect user sing-box configuration.
    binary = Path("/opt/proxyforge-agent/bin/sing-box")
    result = {"installed": binary.is_file(), "running": False, "version": "", "status": "not_installed"}
    if not result["installed"]:
        return result
    try:
        version = subprocess.run([str(binary), "version"], capture_output=True, text=True, timeout=3)
        result["version"] = version.stdout.splitlines()[0][:128] if version.returncode == 0 and version.stdout else ""
        active = subprocess.run(["/usr/bin/systemctl", "is-active", "proxyforge-singbox.service"],
                                capture_output=True, text=True, timeout=3)
        result["running"] = active.returncode == 0
        result["status"] = "running" if result["running"] else "stopped"
    except (OSError, subprocess.TimeoutExpired):
        result["status"] = "unknown"
    return result


def warm_public_addresses(*, ip_reader=None, now_fn=time.monotonic):
    """Refresh the cached external public IPv4/IPv6 (for NAT hosts) in daemon mode."""
    return detect_public_addresses(allow_network=True, ip_reader=ip_reader, now_fn=now_fn)


def read_nftables_capable(path=Path("/var/lib/proxyforge-runtime/nft-capable")):
    """Read root helper's cached nftables capability probe (`True`/`False`/`None`)."""
    try:
        raw = Path(path).read_text(encoding="utf-8").strip()
        if raw == "1":
            return True
        if raw == "0":
            return False
    except OSError:
        pass
    return None


def collect(instance_id, *, allow_network=False):
    system, version = os_release()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)
    try:
        machine_id = hashlib.sha256(Path("/etc/machine-id").read_bytes().strip()).hexdigest()
    except OSError:
        machine_id = ""
    try:
        uptime = max(0, int(float(Path("/proc/uptime").read_text().split()[0])))
    except (OSError, ValueError, IndexError):
        uptime = 0
    addresses = detect_public_addresses(allow_network=allow_network)
    if not addresses and (_PUBLIC_IP_CACHE["ipv4"] or _PUBLIC_IP_CACHE["ipv6"]):
        for cached in (_PUBLIC_IP_CACHE["ipv4"], _PUBLIC_IP_CACHE["ipv6"]):
            if cached and cached not in addresses:
                addresses.append(cached)
    return {"instance_id": instance_id, "hostname": socket.gethostname()[:128],
            "machine_id": machine_id, "os": system, "os_version": version, "arch": arch,
            "agent_version": VERSION, "protocol_version": PROTOCOL_VERSION, "job_protocol_version": 1,
            "runtime_protocol_version": 1 if runtime_available() else 0,
            "deployment_protocol_version": 1 if deployment_available() else 0,
            "landing_protocol_version": 1 if landing_available() else 0,
            "chain_protocol_version": 1 if chain_available() else 0,
            "gost_protocol_version": 1 if gost_available() else 0,
            "self_upgrade_protocol_version": 1 if self_upgrade_available() else 0,
            "bundle_sha256": read_installed_bundle_sha256(),
            "nftables_capable": read_nftables_capable(),
            "uptime": uptime, "addresses": addresses,
            "supported": (system, version) in SUPPORTED and arch in {"amd64", "arm64"},
            "singbox": singbox_status()}
