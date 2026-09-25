"""Read-only inventory; no user-controlled command arguments."""
import hashlib
import platform
from pathlib import Path
import socket
import subprocess

from . import VERSION, PROTOCOL_VERSION
from .runtime_client import available as runtime_available

SUPPORTED = {("debian", "12"), ("debian", "13"), ("ubuntu", "22.04"), ("ubuntu", "24.04")}


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


def collect(instance_id):
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
    return {"instance_id": instance_id, "hostname": socket.gethostname()[:128],
            "machine_id": machine_id, "os": system, "os_version": version, "arch": arch,
            "agent_version": VERSION, "protocol_version": PROTOCOL_VERSION, "job_protocol_version": 1,
            "runtime_protocol_version": 1 if runtime_available() else 0,
            "uptime": uptime, "addresses": [],
            "supported": (system, version) in SUPPORTED and arch in {"amd64", "arm64"},
            "singbox": singbox_status()}
