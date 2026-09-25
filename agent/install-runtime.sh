#!/bin/bash
# Explicit local opt-in, from the same reviewed checkout as the installed Agent.
set -euo pipefail
[[ $EUID -eq 0 && $# -eq 0 ]] || { echo "Usage: sudo bash agent/install-runtime.sh" >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
[[ -d /opt/proxyforge-agent/agent && -f /etc/proxyforge-agent/config.json ]] || { echo "Install Agent first" >&2; exit 1; }
cd /opt/proxyforge-agent
# Verify installed code before importing any of it as root. Isolated Python
# keeps the writable current directory off sys.path during this preflight.
/usr/bin/python3 -I - <<'PY'
from pathlib import Path
root = Path('/opt/proxyforge-agent')
for path in [root, *root.parents, *root.rglob('*')]:
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit('Agent package must be root-owned and not group/world writable')
PY
/usr/bin/python3 -I -c "import sys; sys.path.insert(0, '/opt/proxyforge-agent'); from agent.system_info import os_release, SUPPORTED; import platform; assert os_release() in SUPPORTED and platform.machine() in ('x86_64','aarch64')"
for path in /var/lib/proxyforge-runtime /etc/systemd/system/proxyforge-runtime.socket /etc/systemd/system/proxyforge-runtime.service /etc/systemd/system/proxyforge-singbox.service /opt/proxyforge-agent/bin/sing-box /run/proxyforge-runtime.sock; do
    [[ ! -e $path && ! -L $path ]] || { echo "Existing managed runtime path found; follow the upgrade/recovery guide" >&2; exit 1; }
done
# Refuse vendor/generated units too, not only files under /etc/systemd/system.
for unit in proxyforge-runtime.socket proxyforge-runtime.service proxyforge-singbox.service; do
    state=$(systemctl show --property=LoadState --value "$unit")
    [[ $state == not-found ]] || { echo "Existing runtime unit found" >&2; exit 1; }
done
for file in runtime_spec.py deployment_spec.py runtime_download.py runtime_engine.py runtime_helper.py runtime_client.py singbox-release.json proxyforge-runtime.socket proxyforge-runtime.service proxyforge-singbox.service; do
    [[ -f "$source_dir/$file" ]] || { echo "Incomplete runtime distribution" >&2; exit 1; }
done
if id proxyforge-singbox >/dev/null 2>&1; then
    echo "Existing runtime account found; inspect it locally before provisioning" >&2
    exit 1
fi
useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin proxyforge-singbox
for file in runtime_spec.py deployment_spec.py runtime_download.py runtime_engine.py runtime_helper.py runtime_client.py singbox-release.json; do
    install -m 0644 "$source_dir/$file" "/opt/proxyforge-agent/agent/$file"
done
install -d -m 0755 /var/lib/proxyforge-runtime /var/lib/proxyforge-runtime/releases /opt/proxyforge-agent/bin
ln -s /var/lib/proxyforge-runtime/current/sing-box /opt/proxyforge-agent/bin/sing-box
for unit in proxyforge-runtime.socket proxyforge-runtime.service proxyforge-singbox.service; do
    install -m 0644 "$source_dir/$unit" "/etc/systemd/system/$unit"
done
printf '1\n' > /opt/proxyforge-agent/deployment-protocol
chmod 0644 /opt/proxyforge-agent/deployment-protocol
systemctl daemon-reload
systemctl enable proxyforge-singbox.service
systemctl enable --now proxyforge-runtime.socket
echo "Runtime helper enabled. Request the pinned installation from the Controller; no public listener is configured."
