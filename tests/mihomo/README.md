# Mihomo parser compatibility tests

Both the runtime static validator and these real parser fixtures target
**v1.19.31**. Python tests load the same manifest to check static acceptance and
non-mutation. An intentional difference must specify `static_valid` and a
`static_difference` explanation (e.g. preserving a future TUN stack with a warning).
The CI job also calls the real `build_subscription_config()` with public sample
inputs in `generation/` and passes the emitted YAML to the same binary. The
32 manual fixtures and the generated sample are reported separately.

## Pinned release

`release.json` is the shared source for the version, Linux amd64 compatible asset
and compressed archive SHA256. The digest is published on the
[official release assets page](https://github.com/MetaCubeX/mihomo/releases/expanded_assets/v1.19.31).
The downloader only uses `MetaCubeX/mihomo` GitHub Releases, fails on HTTP or
checksum errors, and verifies the archive before extracting the executable.
No binary is added to the production Docker image or request handlers.

## Run locally (Linux amd64)

From the repository root, with Python 3.9+ (the downloader/parser runner only use
the standard library; generation needs the normal application dependencies):

```bash
python3 scripts/download_mihomo.py --output .local/mihomo/v1.19.31/mihomo
.local/mihomo/v1.19.31/mihomo -v
.local/mihomo/v1.19.31/mihomo -h
python3 scripts/check_mihomo.py --binary .local/mihomo/v1.19.31/mihomo
python3 -m pip install -r requirements.txt
python3 scripts/generate_ci_config.py --output test-results/mihomo/generated-subscription.yaml
python3 scripts/check_mihomo.py --binary .local/mihomo/v1.19.31/mihomo \
  --generated-config test-results/mihomo/generated-subscription.yaml
```

To reproduce CI's network isolation, use Linux `unshare`, `ip` and permission to
create a network namespace (normally via sudo):

```bash
sudo unshare --net -- bash -euc '
  ip link set lo up
  "$1" scripts/generate_ci_config.py --output test-results/mihomo/generated-subscription.yaml
  exec "$1" scripts/check_mihomo.py --binary "$2" --log-dir test-results/mihomo \
    --generated-config test-results/mihomo/generated-subscription.yaml
' _ "$(command -v python3)" "$PWD/.local/mihomo/v1.19.31/mihomo"
```

Only loopback is enabled in this namespace, including IPv6. No proxy service,
airport, subscription token, downloaded rule set or geodata is required. DNS
addresses are documentation IPs; fallback explicitly disables GeoIP filtering.
Ordinary local execution does not enforce network isolation; the CI command does.

The runner invokes `mihomo -t -d <empty temporary home> -f <absolute fixture>`.
The CLI and test-mode behavior are defined by the pinned
[main.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/main.go).
Every case has its own home and process. Environment configuration overrides are
removed. The runner sets `SKIP_SYSTEM_IPV6_CHECK=true`, an upstream
[config/utils.go](https://github.com/MetaCubeX/mihomo/blob/v1.19.31/config/utils.go)
switch, so IPv6 pool parsing is exercised without requiring a global IPv6 address
on the CI host. A fixture's explicit top-level `ipv6: false` still disables that pool.
The default timeout is 30 seconds per invocation; any timeout is a failure.
Logs and `results.json` are written to `test-results/mihomo/` (git-ignored), and CI
uploads them even if a parser expectation fails.

## Real generated subscription

`scripts/generate_ci_config.py` imports the real `main.py` in a temporary working
directory, disables dotenv discovery, and supplies public test credentials for
the temporary runtime store. It does not extract an AST copy or mock the builder.
The temporary directory, environment, import path and module registration are
restored after success or failure. Application diagnostics go to stderr; stdout
(or `--output`) contains only UTF-8 YAML. No production files or Docker changes
are needed.

The input template exercises `_custom_nodes_` expansion, default-node ordering,
flag decoration and rule-target rewriting, plus DNS/TUN and an inline rule
provider. The custom node is a dummy SOCKS5 endpoint on 127.0.0.1:1080; no live
service or airport is needed. Both of the builder's existing static validation
gates execute, followed by serialization and the real parser. Unit tests spy on
the real functions to confirm those calls, protect unrelated DNS/TUN values and
verify isolation from caller `.env`, environment tokens and runtime data.

`--generated-config` may be repeated. Missing or empty files fail before launching
Mihomo, which would otherwise create a default configuration at a missing path.
Generated files, individual parser logs and `results.json` are included in the CI
artifact. The sample is generated and parsed with external network access disabled.

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
- Extended baseline cases: IPv6-only pools, invalid IPv6 family/prefix, insufficient
  IPv4/IPv6 pool capacity, top-level IPv6 disablement, numeric/null edge cases,
  normal DNS mode, Mips stack, TUN field types and proxy policy provider behavior.

Parsing success does not prove network connectivity, route installation, DNS
leak protection, cache behavior, or compatibility with other platforms/versions.
CI deliberately bypasses host IPv6 availability detection to test parsing. It
does not bypass the configuration's top-level IPv6 switch or establish actual
IPv6 connectivity. Platform-dependent TUN behavior is not executed by `-t`.

## Static validation boundaries

`mihomo_compat.py` records the selected raw defaults and field types with pinned
source references. Existing displayed defaults are unchanged; new projections
include use-hosts/use-system-hosts=true, IPv6 timeout=100, fake-IP TTL=1 and the
TUN IPv6 address. Cache raw defaults remain an empty algorithm string and size 0;
the runtime resolver falls back to LRU and 4096 without rewriting YAML.

Only integer representation bounds are hard limits for TTL/cache fields; the
baseline accepts zero and signed negative values. Negative values and float-to-int
coercion produce warnings. Unknown cache strings warn about LRU fallback. Empty
policy lists/strings warn, whereas null policy values are rejected because the
baseline's ToStringSlice panics on null. Normal DNS mode and Mips/case-insensitive
stack names are accepted. These are source/parser-backed fixes to old assumptions.

Future fields are retained as info. Future stack/filter modes and complex matcher
semantics remain partial checks, so a static pass is not a blanket promise that
the pinned binary accepts every user configuration. TUN checks cover types,
numeric widths and address syntax without enforcing server-platform restrictions.

When upgrading, review the pinned source and release digest, update expectations
with evidence, and run both positive and negative cases. Do not convert parser
errors into unconditional success or remove failing cases to pass CI.

## Remaining boundaries and technical debt

- This is one generated scenario, not exhaustive coverage of user YAML, airport
  providers, protocol combinations or every client's Mihomo version.
- Static checks remain intentionally partial for complex matchers/geodata and
  platform-specific behavior; the core's YAML coercions are not all reproduced.
- `main.py` still initializes storage during import. This development helper
  isolates it; an application-factory or pure builder extraction is future work.
- Application Python dependency versions and runner tooling can change. The
  Mihomo tag, architecture, asset and digest are pinned; full build hermeticity is
  outside this change.
- Advanced-field UI, binary caching and first-supported-version tracking are
  optional follow-ups, not required for these parser checks.
