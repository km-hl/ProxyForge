# ProxyForge reference Agent (B1)

This standard-library Python Agent sends inventory to the Controller. It opens
no listening socket, polls no jobs, installs no sing-box, and changes no firewall.
Controller and Agent must both include the B1 protocol (version 1).

## Install from inspected source

Target platforms: Debian 12/13 and Ubuntu 22.04/24.04, amd64/arm64, Python 3.9+,
systemd. The installer rejects other platforms. The test suite exercises
Controller/Agent enrollment and heartbeat on loopback, not a full root installer
matrix on all these operating systems. This is a reference Agent, not a signed
binary release or an automatic upgrade system.

Download a specific reviewed ProxyForge release/commit from the official
repository. Verify that revision through your trusted distribution channel and
inspect `agent/install.sh`, the Python files and systemd unit before running:

```bash
sudo bash agent/install.sh https://your-controller.example
```

From the Controller's **Agent 服务器 → 添加服务器**, generate a registration
token and paste it into the installer's hidden prompt. Do not place it in command
arguments, URLs, shell history, source control or shared screenshots. It expires
after 10 minutes and registers exactly one Agent.

The installer creates an unprivileged `proxyforge-agent` user, copies only the
Agent package to `/opt/proxyforge-agent/agent`, writes credentials with mode 0600
under `/etc/proxyforge-agent` (0700), and enables
`proxyforge-agent.service`. It refuses to overwrite an existing installation.
Install from a root-trusted checkout; do not execute an untrusted installer as root.

Only the normal system CA store is used by the installer. For a private CA, use
the manual enrollment command with `--ca-file /path/to/ca.pem`; keep that CA file
readable by the service user. Certificate verification stays enabled.

## Registration failure and recovery

Registration is never automatically retried. If the response or local credential
write fails after the Controller committed enrollment, the UI may show an Agent
that never sent a heartbeat. Remove that orphan record in the Controller and
issue a **new** token.

The failed installer may have left the package/user/unit in place. Complete
manual enrollment from the inspected installation, running as its service user:

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

A pending config contains no token. If a complete config already contains an
Agent credential, registration refuses to overwrite it. Explicitly revoke that
Agent first and archive/remove its local config before re-enrolling. Never share
that config while troubleshooting.

## Runtime

- Heartbeat: every 30–33 seconds. Failures back off with jitter up to ~303 seconds.
- Controller status: less than 90 seconds online; 90–299 delayed; 300+ offline;
  no heartbeat yet is a separate state. Server receipt time is authoritative.
- A 401/403 stops synchronization with exit 4; systemd does not restart that exit.
- OS support and protocol compatibility are shown separately from online status.
- Only the future independent `proxyforge-singbox.service` and
  `/opt/proxyforge-agent/bin/sing-box` are probed, read-only. Existing user-managed
  sing-box instances are not adopted.
- Machine ID is hashed before reporting and is only a hint. Each enrollment
  generates a new instance ID. Observed IP may be a NAT/proxy address, not a
  public node endpoint.
- Role/tags are inventory labels only. A revoked/removed Agent does not stop any
  already running user services.

Inspect service status with `systemctl status proxyforge-agent` and
`journalctl -u proxyforge-agent`. Logs intentionally omit credentials, response
bodies and controller URLs.

## Development

From the repository root, without root access, select a temporary config path:

```bash
python3 -m agent.main --config /tmp/pf-agent/config.json register \
  --server http://127.0.0.1:8000 --allow-insecure --token-stdin
python3 -m agent.main --config /tmp/pf-agent/config.json run --once
```

Paste the token on stdin. HTTP requires the explicit development flag. HTTPS
always verifies certificates. Cross-origin, same-origin and downgrade redirects
are all rejected rather than forwarding credentials.

## Stop or uninstall locally

First revoke/remove the Agent in the Controller, then on the VPS:

```bash
sudo systemctl disable --now proxyforge-agent.service
sudo rm -- /etc/systemd/system/proxyforge-agent.service
sudo systemctl daemon-reload
```

The package and credential directory are intentionally retained for inspection.
After verifying their paths, an administrator may remove
`/opt/proxyforge-agent` and `/etc/proxyforge-agent` and the dedicated user if no
other service uses it. This never removes sing-box or modifies firewall rules.
There is no remote uninstall or self-upgrade action.
