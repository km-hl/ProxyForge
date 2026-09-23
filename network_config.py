"""Pure, conservative DNS/TUN checks; never resolve addresses or rewrite templates.

Defaults/required fields: Mihomo v1.19.12 config/config.go (DefaultRawConfig,
parseDNS). Newer fields are preserved and reported as outside this baseline.
https://github.com/MetaCubeX/mihomo/blob/v1.19.12/config/config.go
"""
import copy
import ipaddress
import json
from urllib.parse import urlsplit

BASELINE = "Mihomo v1.19.12"
DEFAULTS = {
    "dns": {
        "enable": False, "ipv6": False, "enhanced-mode": "redir-host",
        "respect-rules": False, "prefer-h3": False,
        "fake-ip-range": "198.18.0.1/16", "fake-ip-filter-mode": "blacklist",
        "nameserver": ["https://doh.pub/dns-query", "tls://223.5.5.5:853"],
        "default-nameserver": ["114.114.114.114", "223.5.5.5", "8.8.8.8", "1.0.0.1"],
        "proxy-server-nameserver": [], "direct-nameserver": [], "fallback": [],
        "fake-ip-filter": ["dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"],
    },
    "tun": {
        "enable": False, "stack": "gvisor", "auto-route": True,
        "auto-detect-interface": True, "strict-route": False,
        "dns-hijack": ["0.0.0.0:53"],
    },
}
DNS_LISTS = ("nameserver", "default-nameserver", "proxy-server-nameserver",
             "direct-nameserver", "fallback", "fake-ip-filter")
UDP_HIJACK = {"any:53", "udp://any:53", "0.0.0.0:53", "udp://0.0.0.0:53"}
TCP_HIJACK = {"tcp://any:53", "tcp://0.0.0.0:53"}


def effective_network(config):
    """Apply known defaults to a copy, preserving the distinction from raw YAML.

yaml.v3 null leaves scalar/struct defaults unchanged and clears slices/maps.
Invalid values are left intact for diagnostics, never coerced to bool/string.
"""
    result = copy.deepcopy(DEFAULTS)
    for section in result:
        block = config.get(section)
        if isinstance(block, dict):
            for key, value in block.items():
                if value is None and key in result[section]:
                    if isinstance(result[section][key], list):
                        result[section][key] = []
                else:
                    result[section][key] = copy.deepcopy(value)
    return result


def validate_network_config(config):
    result = {"errors": [], "warnings": [], "info": [], "baseline": BASELINE}

    def add(level, code, path, message):
        result[level].append({"code": code, "path": path, "message": message})

    def error(code, path, message):
        add("errors", code, path, message)

    if not isinstance(config, dict):
        error("root_type", "", "配置根节点必须是 YAML 对象")
        return result
    for section in ("dns", "tun"):
        block = config.get(section)
        if block is not None and not isinstance(block, dict):
            error("section_type", section, "必须是 YAML 对象")
        elif section in config and block is None:
            add("info", "null_defaults", section, "null 保留内核默认；可在底层配置中改为对象后编辑")
    if result["errors"]:
        return result

    effective = effective_network(config)
    dns, tun = effective["dns"], effective["tun"]
    raw_dns, raw_tun = config.get("dns") or {}, config.get("tun") or {}
    # The summary is a JSON API projection, not a second copy of arbitrary
    # advanced YAML (which may contain recursive aliases or non-finite values).
    summary = {section: {key: effective[section][key] for key in defaults}
               for section, defaults in DEFAULTS.items()}
    try:
        json.dumps(summary, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        add("info", "effective_unverified", "dns/tun", "部分字段无法显示为摘要，请按诊断修复或在底层配置中检查")
    else:
        result["effective"] = summary
    result["defaulted"] = [
        section + "." + key for section, defaults in DEFAULTS.items()
        for key in defaults if key not in (config.get(section) or {})
    ]

    bools = {
        "dns": ("enable", "ipv6", "respect-rules", "prefer-h3", "use-hosts",
                "use-system-hosts", "direct-nameserver-follow-policy"),
        "tun": ("enable", "auto-route", "auto-detect-interface", "strict-route", "auto-redirect"),
    }
    for section, fields in bools.items():
        for key in fields:
            value = (config.get(section) or {}).get(key)
            if value is not None and not isinstance(value, bool):
                error("boolean_type", section + "." + key, "必须是 true/false，不能使用字符串或数字")

    def string_list(value, path):
        if value is None:  # yaml.v3 decodes a null slice as empty.
            return []
        if not isinstance(value, list):
            error("list_type", path, "必须是字符串列表")
            return []
        for i, item in enumerate(value):
            if not isinstance(item, str) or not item.strip():
                error("list_item", f"{path}[{i + 1}]", "必须是非空字符串")
        return [item for item in value if isinstance(item, str) and item.strip()]

    lists = {key: string_list(dns.get(key), "dns." + key) for key in DNS_LISTS}
    hijack = string_list(tun.get("dns-hijack"), "tun.dns-hijack")
    mode = dns.get("enhanced-mode")
    if mode not in ("fake-ip", "redir-host"):
        error("dns_mode", "dns.enhanced-mode", "仅支持 fake-ip / redir-host")
    stack = tun.get("stack")
    if not isinstance(stack, str) or not stack.strip():
        error("tun_stack", "tun.stack", "协议栈必须是非空字符串")
    elif stack not in ("system", "gvisor", "mixed"):
        add("warnings", "stack_version", "tun.stack", "协议栈超出校验基线，请确认客户端内核支持；原值保留")

    if dns.get("enable") is True and not lists["nameserver"]:
        error("nameserver_required", "dns.nameserver", "启用 DNS 时 nameserver 不能为空")
    if not lists["default-nameserver"]:
        error("bootstrap_required", "dns.default-nameserver", "Bootstrap 不能为空；删除字段可恢复内核默认")
    if dns.get("respect-rules") is True and not lists["proxy-server-nameserver"]:
        error("proxy_dns_required", "dns.proxy-server-nameserver", "respect-rules 已启用，必须配置节点域名解析 DNS")

    value = dns.get("fake-ip-range")
    if mode == "fake-ip" or "fake-ip-range" in raw_dns:
        try:
            if not isinstance(value, str) or "/" not in value:
                raise ValueError()
            if ipaddress.ip_network(value, strict=False).version != 4:
                raise ValueError()
        except ValueError:
            error("fake_ip_range", "dns.fake-ip-range", "必须是 IPv4 前缀，例如 198.18.0.1/16")

    def address(value, path, bootstrap=False):
        # Validate common forms only. Do not fetch, discard fragments, or treat
        # private client resolvers as server-side SSRF.
        base = value.split("#", 1)[0]
        if base in ("system", "system://"):
            return
        scheme = base.split("://", 1)[0] if "://" in base else "udp"
        if scheme not in ("udp", "tcp", "tls", "https", "quic"):
            add("info", "address_unverified", path, "高级 DNS 地址保留，未验证此协议的客户端兼容性")
            return
        try:
            try:
                host = str(ipaddress.ip_address(base))
            except ValueError:
                parsed = urlsplit(base if "://" in base else "udp://" + base)
                host = parsed.hostname
                if not host or parsed.username is not None or any(c.isspace() for c in base):
                    raise ValueError()
                if parsed.port is not None and not 1 <= parsed.port <= 65535:
                    raise ValueError()
            if bootstrap:
                ipaddress.ip_address(host)
        except (ValueError, TypeError):
            error("bootstrap_address" if bootstrap else "dns_address", path,
                  "Bootstrap 主机必须是 IP（或 system）" if bootstrap else "DNS 地址格式或端口无效")

    for key in DNS_LISTS:
        if key == "fake-ip-filter":
            continue
        for i, value in enumerate(lists[key]):
            address(value, f"dns.{key}[{i + 1}]", key == "default-nameserver")
    for i, value in enumerate(hijack):
        try:
            parsed = urlsplit(value if "://" in value else "udp://" + value)
            if parsed.scheme not in ("udp", "tcp") or not parsed.hostname or parsed.port is None:
                raise ValueError()
            if not 1 <= parsed.port <= 65535:
                raise ValueError()
            if parsed.hostname != "any":
                ipaddress.ip_address(parsed.hostname)
        except ValueError:
            error("hijack_address", f"tun.dns-hijack[{i + 1}]", "需要 UDP/TCP 的 IP:端口或 any:端口")

    policies = raw_dns.get("nameserver-policy")
    if policies is not None:
        if not isinstance(policies, dict):
            error("policy_type", "dns.nameserver-policy", "必须是 matcher 到 DNS 地址的映射")
        else:
            providers = config.get("rule-providers")
            providers = providers if isinstance(providers, dict) else {}
            for key, value in policies.items():
                path = "dns.nameserver-policy." + str(key)
                if not isinstance(key, str) or not key.strip():
                    error("policy_key", path, "匹配规则必须是非空字符串")
                    continue
                values = [value] if isinstance(value, str) else string_list(value, path)
                if not values:
                    error("policy_empty", path, "策略 DNS 列表不能为空")
                for item in values:
                    address(item, path)
                if key.startswith("rule-set:"):
                    for name in key[9:].split(","):
                        provider = providers.get(name)
                        if not isinstance(provider, dict):
                            error("policy_reference", path, "引用的 rule-provider 不存在")
                        elif provider.get("behavior") == "ipcidr":
                            error("policy_behavior", path, "DNS 策略不能使用 ipcidr 类型的 rule-provider")
                elif key.startswith("geosite:"):
                    add("info", "geodata_unverified", path, "依赖客户端 geodata，本检查未下载验证")
                else:
                    add("info", "matcher_unverified", path, "保留 Mihomo matcher；复杂匹配语法由客户端验证")

    if tun.get("enable") is True:
        if dns.get("enable") is not True:
            add("warnings", "tun_without_dns", "dns.enable", "TUN 已开启，但 Mihomo DNS 未启用")
        if not hijack:
            add("warnings", "hijack_missing", "tun.dns-hijack", "TUN 已开启，但 DNS Hijack 为空")
        elif not (UDP_HIJACK.intersection(hijack) and TCP_HIJACK.intersection(hijack)):
            add("warnings", "hijack_partial", "tun.dns-hijack", "未同时配置通用 UDP/TCP 53 映射；自定义项仅覆盖其匹配范围")
        if tun.get("strict-route") is not True:
            add("warnings", "strict_route_advice", "tun.strict-route", "Windows 多网卡场景可考虑 Strict Route，需评估应用兼容性")
    if tun.get("strict-route") is True and tun.get("auto-route") is False:
        add("warnings", "strict_route_inactive", "tun.auto-route", "Strict Route 依赖 auto-route，目前未开启")
    if dns.get("respect-rules") is True and dns.get("prefer-h3") is True:
        add("warnings", "respect_h3", "dns.prefer-h3", "不建议同时启用 respect-rules 和 prefer-h3")
    if lists["direct-nameserver"]:
        add("info", "direct_policy", "dns.direct-nameserver", "DIRECT DNS 是否遵循策略取决于 direct-nameserver-follow-policy")
    if dns.get("fake-ip-filter-mode") not in ("blacklist", "whitelist"):
        add("info", "filter_unverified", "dns.fake-ip-filter-mode", "高级过滤模式保留，请在底层配置中编辑并确认内核版本")
    known_dns = set(DEFAULTS["dns"]) | set(bools["dns"]) | {"nameserver-policy"}
    known_tun = set(DEFAULTS["tun"]) | set(bools["tun"])
    if set(raw_dns) - known_dns or set(raw_tun) - known_tun:
        add("info", "advanced_unverified", "dns/tun", "包含未完整验证的高级字段；原值保留")
    encrypted = {}
    for key in DNS_LISTS:
        if key != "fake-ip-filter":
            values = lists[key]
            encrypted[key] = {"total": len(values), "encrypted": sum(
                item.startswith(("https://", "tls://", "quic://")) for item in values)}
    if isinstance(policies, dict):
        values = [item for value in policies.values() for item in
                  ([value] if isinstance(value, str) else value if isinstance(value, list) else [])
                  if isinstance(item, str)]
        encrypted["nameserver-policy"] = {"total": len(values), "encrypted": sum(
            item.startswith(("https://", "tls://", "quic://")) for item in values)}
    result["encryption"] = encrypted
    active = dns.get("enable") is True or tun.get("enable") is True
    partial = any(item["code"].endswith("unverified") for item in result["info"])
    result["status"] = ("error" if result["errors"] else "warning" if result["warnings"]
                        else "neutral" if not active or partial else "success")
    return result


def network_error_messages(result):
    return [f"{item['path']}: {item['message']}" if item["path"] else item["message"]
            for item in result["errors"]]
