"""Pure, conservative DNS/TUN checks; never resolve addresses or rewrite templates.

Defaults and field definitions live in mihomo_compat.py, pinned to v1.19.31.
This module projects raw defaults; it does not simulate a client's runtime.
"""
import copy
import ipaddress
import json
import math
from urllib.parse import urlsplit

from mihomo_compat import (
    BASELINE, DEFAULTS, BOOL_FIELDS, INTEGER_FIELDS, KNOWN_DNS_FIELDS,
    KNOWN_TUN_FIELDS, DNS_MODES, TUN_STACKS, CACHE_ALGORITHMS,
    TUN_PREFIX_LISTS, TUN_STRING_LISTS, TUN_INTEGER_LISTS,
)
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
                    elif key.endswith("nameserver-policy"):
                        result[section][key] = {}
                elif section == "dns" and key == "fallback-filter" and isinstance(value, dict):
                    # This is a Go struct, not a map: omitted/null scalar
                    # members keep defaults; null slices clear them.
                    for name, item in value.items():
                        default = result[section][key].get(name)
                        if item is None and name in result[section][key]:
                            if isinstance(default, list):
                                result[section][key][name] = []
                        else:
                            result[section][key][name] = copy.deepcopy(item)
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

    for section, fields in BOOL_FIELDS.items():
        for key in fields:
            value = (config.get(section) or {}).get(key)
            if value is not None and not isinstance(value, bool):
                error("boolean_type", section + "." + key, "必须是 true/false，不能使用字符串或数字")

    def string_list(value, path, allow_empty=False):
        if value is None:  # yaml.v3 decodes a null slice as empty.
            return []
        if not isinstance(value, list):
            error("list_type", path, "必须是字符串列表")
            return []
        for i, item in enumerate(value):
            if not isinstance(item, str) or (not allow_empty and not item.strip()):
                error("list_item", f"{path}[{i + 1}]", "必须是非空字符串")
        return [item for item in value if isinstance(item, str) and (allow_empty or item.strip())]

    def integer(value, path, bounds):
        if value is None:
            return
        if type(value) not in (int, float) or (isinstance(value, float) and not math.isfinite(value)):
            error("integer_type", path, "必须是整数，不能使用布尔值、字符串或非有限数值")
        elif not bounds[0] <= value <= bounds[1]:
            error("integer_range", path, "超出 Mihomo baseline 字段整数范围")
        elif isinstance(value, float):
            add("warnings", "integer_coercion", path, "内核会将浮点数转换为整数；建议显式使用整数，原值保留")
        elif (bounds[1] > 2 ** 32 - 1 and not -(2 ** 31) <= value < 2 ** 31
              and path not in ("tun.udp-timeout", "tun.icmp-timeout")):
            add("warnings", "integer_platform", path, "数值可能超出 32 位客户端范围；具体支持取决于客户端平台")

    for section, fields in INTEGER_FIELDS.items():
        for key, bounds in fields.items():
            integer((config.get(section) or {}).get(key), section + "." + key, bounds)
    for path, value in (("dns.listen", dns.get("listen")),
                        ("dns.cache-algorithm", dns.get("cache-algorithm")),
                        ("tun.device", tun.get("device"))):
        if not isinstance(value, str):
            error("string_type", path, "必须是字符串")
    algorithm = dns.get("cache-algorithm")
    if isinstance(algorithm, str) and algorithm not in CACHE_ALGORITHMS:
        add("warnings", "cache_algorithm_fallback", "dns.cache-algorithm",
            "baseline 对非 arc 值回退到 LRU；请确认是否为拼写错误或新版本算法")
    for key in ("fake-ip-ttl", "cache-max-size"):
        value = dns.get(key)
        if type(value) in (int, float) and value < 0:
            add("warnings", "negative_dns_value", "dns." + key,
                "内核 parser 接受负数，但运行效果需确认；建议使用非负整数")

    lists = {key: string_list(dns.get(key), "dns." + key) for key in DNS_LISTS}
    hijack = string_list(tun.get("dns-hijack"), "tun.dns-hijack")
    mode = dns.get("enhanced-mode")
    mode = mode.lower() if isinstance(mode, str) else mode
    if mode not in DNS_MODES:
        error("dns_mode", "dns.enhanced-mode", "支持 normal / fake-ip / redir-host")
    stack = tun.get("stack")
    if not isinstance(stack, str) or not stack.strip():
        error("tun_stack", "tun.stack", "协议栈必须是非空字符串")
    elif stack.lower() not in TUN_STACKS:
        add("warnings", "stack_version", "tun.stack", "协议栈超出校验基线，请确认客户端内核支持；原值保留")

    if dns.get("enable") is True and not lists["nameserver"]:
        error("nameserver_required", "dns.nameserver", "启用 DNS 时 nameserver 不能为空")
    if not lists["default-nameserver"]:
        error("bootstrap_required", "dns.default-nameserver", "Bootstrap 不能为空；删除字段可恢复内核默认")
    if dns.get("respect-rules") is True and not lists["proxy-server-nameserver"]:
        error("proxy_dns_required", "dns.proxy-server-nameserver", "respect-rules 已启用，必须配置节点域名解析 DNS")

    def prefix(value):
        if not isinstance(value, str) or "/" not in value or "%" in value:
            raise ValueError()
        bits = value.rsplit("/", 1)[1]
        if not bits.isascii() or not bits.isdigit():
            raise ValueError()
        return ipaddress.ip_network(value, strict=False)

    for key, version in (("fake-ip-range", 4), ("fake-ip-range6", 6)):
        value = dns.get(key)
        if value == "":
            continue
        if version == 6 and config.get("ipv6") is False and isinstance(value, str):
            # parseIPV6 clears this string before parseDNS. Keep the raw value
            # and the environment notice below, without rejecting an unused pool.
            continue
        try:
            pool = prefix(value)
            if pool.version != version:
                raise ValueError()
            if mode == "fake-ip" and pool.num_addresses < 8:
                error("fake_ip_capacity", "dns." + key, "Fake-IP 地址池过小，内核无法创建可用地址池")
        except ValueError:
            error("fake_ip_range" if version == 4 else "fake_ip_range6", "dns." + key,
                  f"必须是合法 IPv{version} CIDR；允许空字符串以禁用此地址池")
    if dns.get("fake-ip-range6"):
        add("info", "ipv6_environment_unverified", "dns.fake-ip-range6",
            "IPv6 地址池是否生效取决于顶层 ipv6、客户端 IPv6 环境和 DNS 查询设置；原值保留")
    if mode == "fake-ip" and dns.get("fake-ip-range") == "" and (
            dns.get("fake-ip-range6") == "" or config.get("ipv6") is False):
        error("fake_ip_pools_empty", "dns.fake-ip-range", "Fake-IP 模式需要至少一个可用地址池；顶层 ipv6: false 会禁用 IPv6 池")

    for key in TUN_PREFIX_LISTS + ("loopback-address",):
        for i, item in enumerate(string_list(raw_tun.get(key), "tun." + key)):
            try:
                if key == "loopback-address":
                    ipaddress.ip_address(item)
                else:
                    prefix(item)
            except ValueError:
                error("tun_address", f"tun.{key}[{i + 1}]", "必须是合法 IP 地址" if key == "loopback-address" else "必须是合法 IP CIDR")
    for key in TUN_STRING_LISTS:
        string_list(raw_tun.get(key), "tun." + key, allow_empty=True)
    for key, bounds in TUN_INTEGER_LISTS.items():
        values = raw_tun.get(key)
        if values is not None:
            if not isinstance(values, list):
                error("list_type", "tun." + key, "必须是整数列表")
            else:
                for i, value in enumerate(values):
                    integer(value, f"tun.{key}[{i + 1}]", bounds)
    if set(raw_tun) & (KNOWN_TUN_FIELDS - set(DEFAULTS["tun"])):
        add("info", "tun_platform_unverified", "tun",
            "高级 TUN 字段已作基础类型检查；路由、接口、UID 与平台支持由客户端运行时决定")

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

    policy_fields = ("nameserver-policy", "proxy-server-nameserver-policy")
    for field in policy_fields:
        policies = raw_dns.get(field)
        if policies is None:
            continue
        if not isinstance(policies, dict):
            error("policy_type", "dns." + field, "必须是 matcher 到 DNS 地址的映射")
        else:
            if field == "proxy-server-nameserver-policy" and policies and not lists["proxy-server-nameserver"]:
                error("proxy_policy_dns_required", "dns.proxy-server-nameserver",
                      "非空 proxy-server-nameserver-policy 必须配置 proxy-server-nameserver，与 respect-rules 无关")
            providers = config.get("rule-providers")
            providers = providers if isinstance(providers, dict) else {}
            for key, value in policies.items():
                path = "dns." + field + "." + str(key)
                if not isinstance(key, str) or not key.strip():
                    error("policy_key", path, "匹配规则必须是非空字符串")
                    continue
                if value is None:
                    error("policy_null", path, "策略值不能为 null，baseline parser 无法安全处理该值")
                    continue
                values = [value] if isinstance(value, str) else string_list(value, path, allow_empty=True)
                if isinstance(value, (list, str)) and (not values or "" in values):
                    add("warnings", "policy_empty", path, "内核允许空策略 DNS；实际解析行为需确认，原值保留")
                for item in values:
                    if item:
                        address(item, path)
                if key.lower().startswith("rule-set:"):
                    for name in key[9:].split(","):
                        provider = providers.get(name)
                        if not isinstance(provider, dict):
                            error("policy_reference", path, "引用的 rule-provider 不存在")
                        elif provider.get("behavior") == "ipcidr":
                            error("policy_behavior", path, "DNS 策略不能使用 ipcidr 类型的 rule-provider")
                        elif provider.get("behavior") == "classical":
                            add("warnings", "policy_classical", path, "classical rule-provider 仅使用其中的域名规则")
                elif key.lower().startswith("geosite:"):
                    add("info", "geodata_unverified", path, "依赖客户端 geodata，本检查未下载验证")
                else:
                    add("info", "matcher_unverified", path, "保留 Mihomo matcher；复杂匹配语法由客户端验证")

    fallback = dns.get("fallback-filter")
    if not isinstance(fallback, dict):
        error("fallback_filter_type", "dns.fallback-filter", "必须是 YAML 对象")
    else:
        if not isinstance(fallback.get("geoip"), bool):
            error("boolean_type", "dns.fallback-filter.geoip", "必须是 true/false")
        if not isinstance(fallback.get("geoip-code"), str):
            error("string_type", "dns.fallback-filter.geoip-code", "必须是字符串")
        for key in ("ipcidr", "domain", "geosite"):
            values = string_list(fallback.get(key), "dns.fallback-filter." + key)
            if key == "ipcidr" and lists["fallback"]:
                for i, value in enumerate(values):
                    try:
                        prefix(value)
                    except ValueError:
                        error("fallback_prefix", f"dns.fallback-filter.ipcidr[{i + 1}]", "必须是合法 IP CIDR")
        if lists["fallback"] and (fallback.get("geoip") is True or fallback.get("geosite")):
            add("info", "geodata_unverified", "dns.fallback-filter", "依赖客户端 geodata，本检查未下载验证")
        if set(fallback) - set(DEFAULTS["dns"]["fallback-filter"]):
            add("info", "advanced_unverified", "dns.fallback-filter", "保留未验证的高级过滤字段")

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
    filter_mode = dns.get("fake-ip-filter-mode")
    if not isinstance(filter_mode, str):
        error("filter_mode_type", "dns.fake-ip-filter-mode", "必须是字符串")
    elif filter_mode.lower() not in ("blacklist", "whitelist"):
        add("info", "filter_unverified", "dns.fake-ip-filter-mode", "高级过滤模式保留，请在底层配置中编辑并确认内核版本")
    if set(raw_dns) - KNOWN_DNS_FIELDS or set(raw_tun) - KNOWN_TUN_FIELDS:
        add("info", "advanced_unverified", "dns/tun", "包含未完整验证的高级字段；原值保留")
    encrypted = {}
    for key in DNS_LISTS:
        if key != "fake-ip-filter":
            values = lists[key]
            encrypted[key] = {"total": len(values), "encrypted": sum(
                item.startswith(("https://", "tls://", "quic://")) for item in values)}
    for field in policy_fields:
        policies = raw_dns.get(field)
        if isinstance(policies, dict):
            values = [item for value in policies.values() for item in
                      ([value] if isinstance(value, str) else value if isinstance(value, list) else [])
                      if isinstance(item, str)]
            encrypted[field] = {"total": len(values), "encrypted": sum(
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
