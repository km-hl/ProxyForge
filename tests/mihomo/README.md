# Mihomo parser compatibility tests

This is the first compatibility phase: real parser fixtures and CI infrastructure.
The runtime static validator remains on **v1.19.12**. These fixtures target
**v1.19.31**; they do not yet compare static-validator diagnostics or call
`build_subscription_config()`. Those integrations belong to subsequent phases.

## Pinned release

`release.json` is the shared source for the version, Linux amd64 compatible asset
and compressed archive SHA256. The digest is published on the
[official release assets page](https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.31).
The downloader only uses `MetaCubeX/mihomo` GitHub Releases, fails on HTTP or
checksum errors, and verifies the archive before extracting the executable.
No binary is added to the production Docker image or request handlers.

## Run locally (Linux amd64)

From the repository root, with Python 3.9+ (no Python packages required):

```bash
python3 scripts/download_mihomo.py --output .local/mihomo/v1.19.31/mihomo
.local/mihomo/v1.19.31/mihomo -v
.local/mihomo/v1.19.31/mihomo -h
python3 scripts/check_mihomo.py --binary .local/mihomo/v1.19.31/mihomo
```

To reproduce CI's network isolation, use Linux `unshare`, `ip` and permission to
create a network namespace (normally via sudo):

```bash
sudo unshare --net -- bash -euc 'ip link set lo up; exec "$@"' _ \
  "$(command -v python3)" scripts/check_mihomo.py \
  --binary .local/mihomo/v1.19.31/mihomo --log-dir test-results/mihomo
```

Only loopback is enabled in this namespace, including IPv6. No proxy service,
airport, subscription token, downloaded rule set or geodata is required. DNS
addresses are documentation IPs; fallback explicitly disables GeoIP filtering.
Ordinary local execution does not enforce network isolation; the CI command does.

The runner invokes `mihomo -t -d <empty temporary home> -f <absolute fixture>`.
The CLI and test-mode behavior are defined by the pinned
[main.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/main.go).
Every case has its own home and process. Environment configuration overrides are
removed. The default timeout is 30 seconds per invocation; any timeout is a failure.
Logs and `results.json` are written to `test-results/mihomo/` (git-ignored), and CI
uploads them even if a parser expectation fails.

## Coverage and maintenance

`cases.json` lists every YAML fixture exactly once. Positive cases require exit 0
and the parser success marker. Negative cases require exit 1, the failure marker
and a specific diagnostic; a crash or unrelated error does not satisfy a case.

- Positive: minimal defaults, Fake-IP and zero TTL, scalar/list DNS policies,
  inline rule-provider references, proxy DNS policies, basic/strict TUN,
  advanced DNS with IPv6/cache/fallback, null blocks and null scalars.
- Negative: empty/null nameservers with DNS enabled, wrong DNS field type,
  missing proxy DNS policy dependency, wrong IPv4 pool family, both pools empty,
  and a missing rule-provider reference.

Parsing success does not prove network connectivity, route installation, DNS
leak protection, cache behavior, or compatibility with other platforms/versions.
In particular the core may discard IPv6 settings based on environment support;
accepting the advanced fixture alone does not prove its IPv6 pool was exercised.

When upgrading, review the pinned source and release digest, update expectations
with evidence, and run both positive and negative cases. Do not convert parser
errors into unconditional success or remove failing cases to pass CI.
