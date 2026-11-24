# ProxyForge Agent (0.6.0)

[中文运维与恢复说明](README.zh-CN.md) · [Agent Install Guide (中文)](../docs/AGENT_INSTALL.md)

The ProxyForge Agent runs purely on the **system Python 3.9+ standard library** (no third-party Python packages). It connects outbound over HTTPS to report host inventory, send heartbeats, and execute allowlisted jobs without opening any public control listener.

When enabled, the local Unix-socket privileged helper (`proxyforge-runtime.socket`) isolates root operations for managing `sing-box`, `Caddy`, `go-gost`, `nftables` per-user traffic counters, host node adoption, and verified self-upgrades.

## Installation & Upgrades

- **Recommended (one-line installer)**: Configure `PROXYFORGE_PUBLIC_URL` on the Controller and copy the `/api/agent/install.sh` command from **Servers & Nodes → Add Server** (supports `--runtime`, `--with-gost`, `--adopt-scan`, `--gh-proxy`, `--upgrade`, `--reinstall`). See [Agent Install Guide](../docs/AGENT_INSTALL.md).
- **From a trusted source checkout** (root-owned, not group/world writable):
  ```bash
  sudo bash agent/install.sh https://your-controller.example
  # Optional local privileged runtime helper:
  sudo bash agent/install-runtime.sh
  ```
- **Silent self-upgrade**: Agents reporting `self_upgrade_protocol_version=1` compare `latest_bundle_sha256` on heartbeat, download and SHA256-verify the Controller bundle, atomically update files via the helper, and restart only affected units.
- **Upgrading legacy Agents**: Re-run the Controller quick-install command with `--upgrade` to update code and systemd units in place while preserving `/etc/proxyforge-agent/config.json`.

Supported platforms: **Debian 12/13**, **Ubuntu 22.04/24.04** (`amd64` / `arm64`), `systemd`, Python 3.9+. Credentials are stored with mode `0600` under `/etc/proxyforge-agent/` (`0700`) and run as the unprivileged `proxyforge-agent` account. For a private CA, pass `--ca-file /path/to/ca.pem` during manual registration.

## Registration Recovery

Registration is never retried automatically. If enrollment succeeded on the Controller but failed before local credentials were saved, delete the never-seen record in the Controller, issue a new 10-minute token, and run:

```bash
cd /opt/proxyforge-agent
read -r -s -p 'New registration token: ' registration_token
printf '\n'
printf '%s\n' "$registration_token" | sudo -u proxyforge-agent /usr/bin/python3 -m agent.main \
  --config /etc/proxyforge-agent/config.json register \
  --server https://your-controller.example --token-stdin
unset registration_token
sudo systemctl daemon-reload
sudo systemctl enable --now proxyforge-agent
```

## Troubleshooting & Uninstall

- Heartbeats run every 30–33s (exponential backoff up to ~303s on failures). HTTP `401/403` (revoked credential) exits with code `4` and stops systemd restarts.
- Inspect service status and logs (credentials and Controller URLs are never logged):
  ```bash
  sudo systemctl status proxyforge-agent proxyforge-runtime.socket proxyforge-singbox --no-pager
  sudo journalctl -u proxyforge-agent -n 50 --no-pager
  sudo journalctl -u proxyforge-runtime -n 50 --no-pager
  ```
- Stop and disable locally (revoke/remove the server in the Controller first):
  ```bash
  sudo systemctl disable --now proxyforge-agent.service proxyforge-runtime.socket \
    proxyforge-singbox.service proxyforge-caddy.service proxyforge-gost.service 2>/dev/null || true
  ```
  After confirming backups, remove the unit files under `/etc/systemd/system/proxyforge-*` along with `/opt/proxyforge-agent`, `/etc/proxyforge-agent`, and `/var/lib/proxyforge-runtime` as needed.

## Local Verification

```bash
python3 -S -m agent.main --help
python3 -S -m unittest discover -s tests -p test_runtime_engine.py -v
python3 -S -m unittest discover -s tests -p test_nft_users.py -v
python3 -S -m unittest discover -s tests -p test_agent_self_upgrade.py -v
```
