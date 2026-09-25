#!/bin/bash
# Install only from a downloaded, reviewed, pinned checkout. No curl | shell.
set -euo pipefail
if [[ $EUID -ne 0 || $# -ne 1 ]]; then
    echo "Usage: sudo bash agent/install.sh https://controller.example" >&2
    exit 1
fi
server=$1
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -x /usr/bin/python3 && -x /usr/bin/systemctl ]] || { echo "Python3 and systemd required"; exit 1; }
/usr/bin/python3 - "$server" <<'PY'
import platform, sys, urllib.parse
from pathlib import Path
values = {}
for line in Path("/etc/os-release").read_text().splitlines():
    key, _, value = line.partition("=")
    values[key] = value.strip('"')
supported = {("debian","12"),("debian","13"),("ubuntu","22.04"),("ubuntu","24.04")}
if (values.get("ID"), values.get("VERSION_ID")) not in supported or platform.machine() not in {"x86_64","aarch64"}:
    raise SystemExit("Unsupported distribution or architecture")
url=urllib.parse.urlsplit(sys.argv[1])
if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
    raise SystemExit("A root HTTPS controller URL is required")
if sys.version_info < (3,9):
    raise SystemExit("Python 3.9+ required")
PY
if [[ -e /opt/proxyforge-agent || -e /etc/proxyforge-agent || -e /etc/systemd/system/proxyforge-agent.service ]]; then
    echo "Existing Agent installation found. Follow the documented recovery/upgrade procedure; nothing overwritten." >&2
    exit 1
fi
for file in __init__.py main.py client.py system_info.py jobs.py job_lease.py runtime_spec.py deployment_spec.py runtime_download.py runtime_engine.py runtime_client.py singbox-release.json proxyforge-agent.service; do
    [[ -f "$source_dir/$file" ]] || { echo "Incomplete Agent distribution"; exit 1; }
done
if ! id proxyforge-agent >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin proxyforge-agent
fi
install -d -m 0755 /opt/proxyforge-agent/agent
for file in __init__.py main.py client.py system_info.py jobs.py job_lease.py runtime_spec.py deployment_spec.py runtime_download.py runtime_engine.py runtime_client.py singbox-release.json; do
    install -m 0644 "$source_dir/$file" "/opt/proxyforge-agent/agent/$file"
done
install -d -m 0700 -o proxyforge-agent -g proxyforge-agent /etc/proxyforge-agent
install -m 0644 "$source_dir/proxyforge-agent.service" /etc/systemd/system/proxyforge-agent.service
read -r -s -p "One-time registration token (hidden): " registration_token </dev/tty
printf '\n'
trap 'unset registration_token' EXIT
cd /opt/proxyforge-agent
printf '%s\n' "$registration_token" | runuser -u proxyforge-agent -- /usr/bin/python3 -m agent.main \
    --config /etc/proxyforge-agent/config.json register --server "$server" --token-stdin
unset registration_token
systemctl daemon-reload
systemctl enable --now proxyforge-agent.service
echo "Inventory Agent installed. No sing-box deployment or firewall changes were made."
