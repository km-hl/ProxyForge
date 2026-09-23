"""Static compatibility facts, not values to write into user templates.

Sources pinned to https://github.com/MetaCubeX/mihomo/tree/v1.19.31:
config/config.go: RawDNS, RawTun, DefaultRawConfig, parseDNS, parseDomainRuleSet;
constant/{dns,tun}.go: text enums; component/fakeip/pool.go: pool capacity;
dns/resolver.go: cache runtime fallback (distinct from RawDNS defaults).
"""

BASELINE = "Mihomo v1.19.31"
DNS_DEFAULTS = {
    "enable": False, "ipv6": False, "enhanced-mode": "redir-host",
    "respect-rules": False, "prefer-h3": False,
    "use-hosts": True, "use-system-hosts": True, "ipv6-timeout": 100,
    "fake-ip-range": "198.18.0.1/16", "fake-ip-range6": "",
    "fake-ip-ttl": 1, "fake-ip-filter-mode": "blacklist",
    "nameserver": ["https://doh.pub/dns-query", "tls://223.5.5.5:853"],
    "default-nameserver": ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"],
    "proxy-server-nameserver": [], "direct-nameserver": [], "fallback": [],
    "fake-ip-filter": ["dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"],
    "fallback-lazy-query": False, "direct-nameserver-follow-policy": False,
    "listen": "", "listen-routing-mark": 0,
    # RawConfig zero values: newCache later maps these to lru and 4096.
    "cache-algorithm": "", "cache-max-size": 0,
    "nameserver-policy": {}, "proxy-server-nameserver-policy": {},
    "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": [],
                        "geosite": [], "domain": []},
}
TUN_DEFAULTS = {
    "enable": False, "stack": "gvisor", "device": "", "auto-route": True,
    "auto-detect-interface": True, "strict-route": False,
    "dns-hijack": ["0.0.0.0:53"], "inet6-address": ["fdfe:dcba:9876::1/126"],
}
DEFAULTS = {"dns": DNS_DEFAULTS, "tun": TUN_DEFAULTS}
BOOL_FIELDS = {
    "dns": ("enable", "ipv6", "respect-rules", "prefer-h3", "use-hosts",
            "use-system-hosts", "direct-nameserver-follow-policy", "fallback-lazy-query"),
    "tun": ("enable", "auto-route", "auto-detect-interface", "strict-route", "auto-redirect",
            "gso", "endpoint-independent-nat", "disable-icmp-forwarding", "recvmsgx", "sendmsgx"),
}
# int/uint use the CI baseline's 64-bit architecture. Values outside 32-bit
# portability get a warning, not an invented rejection of valid amd64 input.
INT64 = (-(2 ** 63), 2 ** 63 - 1)
UINT64 = (0, 2 ** 64 - 1)
UINT32 = (0, 2 ** 32 - 1)
INTEGER_FIELDS = {
    "dns": {"ipv6-timeout": UINT64, "fake-ip-ttl": INT64,
            "cache-max-size": INT64, "listen-routing-mark": INT64},
    "tun": {**dict.fromkeys(("mtu", "gso-max-size", "auto-redirect-input-mark",
                             "auto-redirect-output-mark"), UINT32),
            **dict.fromkeys(("iproute2-table-index", "iproute2-rule-index",
                             "auto-redirect-iproute2-fallback-rule-index", "udp-timeout",
                             "icmp-timeout", "file-descriptor", "processors-per-channel"), INT64)},
}
TUN_PREFIX_LISTS = ("inet6-address", "route-address", "route-exclude-address",
                    "inet4-route-address", "inet6-route-address",
                    "inet4-route-exclude-address", "inet6-route-exclude-address")
TUN_STRING_LISTS = ("route-address-set", "route-exclude-address-set", "include-interface",
                   "exclude-interface", "include-uid-range", "exclude-uid-range",
                   "exclude-src-port-range", "exclude-dst-port-range", "include-package",
                   "exclude-package", "include-mac-address", "exclude-mac-address")
TUN_INTEGER_LISTS = {"include-uid": UINT32, "exclude-uid": UINT32,
                     "exclude-src-port": (0, 65535), "exclude-dst-port": (0, 65535),
                     "include-android-user": INT64}
KNOWN_DNS_FIELDS = frozenset(DNS_DEFAULTS)
KNOWN_TUN_FIELDS = (frozenset(TUN_DEFAULTS) | set(BOOL_FIELDS["tun"]) |
                    set(INTEGER_FIELDS["tun"]) | set(TUN_PREFIX_LISTS) |
                    set(TUN_STRING_LISTS) | set(TUN_INTEGER_LISTS) | {"loopback-address"})
DNS_MODES = ("normal", "fake-ip", "redir-host")
TUN_STACKS = ("system", "gvisor", "mixed", "mips")
CACHE_ALGORITHMS = ("", "lru", "arc")
