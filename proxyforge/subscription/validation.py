"""Validate nodes and complete Mihomo configurations without runtime state."""
import base64
import ipaddress
import re
from typing import Any, Dict, List

from proxyforge.config.network_config import validate_network_config, network_error_messages
from .nodes import CUSTOM_NODES_SOURCE


class ConfigValidationError(ValueError):
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("\n".join(errors))


def _is_valid_port(value: Any) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False


def _has_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_non_negative_integer(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return int(value) >= 0 and str(value).strip().isdigit()
    except (TypeError, ValueError):
        return False


def _is_positive_integer(value: Any) -> bool:
    return _is_non_negative_integer(value) and int(value) > 0


def _is_valid_ip_address(value: Any, version: int) -> bool:
    if not _has_text(value):
        return False
    try:
        return ipaddress.ip_address(value.strip()).version == version
    except ValueError:
        return False


def _is_valid_wireguard_key(value: Any) -> bool:
    if not _has_text(value):
        return False
    normalized = value.strip()
    if len(normalized) != 44:
        return False
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (TypeError, ValueError):
        return False
    return len(decoded) == 32


def _is_valid_wireguard_reserved(value: Any) -> bool:
    if isinstance(value, list):
        return (
            len(value) == 3
            and all(
                isinstance(item, int)
                and not isinstance(item, bool)
                and 0 <= item <= 255
                for item in value
            )
        )
    if not _has_text(value):
        return False
    try:
        return len(base64.b64decode(value.strip(), validate=True)) == 3
    except (TypeError, ValueError):
        return False


def _is_valid_ip_network_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    try:
        return all(
            _has_text(item) and bool(ipaddress.ip_network(item.strip(), strict=False))
            for item in value
        )
    except ValueError:
        return False


def _is_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(_has_text(item) for item in value)


def validate_proxy_nodes(proxies: Any, location: str = "proxies") -> List[str]:
    errors = []
    if not isinstance(proxies, list):
        return [f"{location} 必须是列表"]

    seen_names = set()
    for index, proxy in enumerate(proxies, 1):
        prefix = f"{location}[{index}]"
        if not isinstance(proxy, dict):
            errors.append(f"{prefix} 必须是对象")
            continue
        name = proxy.get("name")
        proxy_type = str(proxy.get("type", "")).lower()
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{prefix} 缺少有效的 name")
        elif name in seen_names:
            errors.append(f"{prefix} 节点名称重复: {name}")
        else:
            seen_names.add(name)
        if not proxy_type:
            errors.append(f"{prefix} 缺少 type")

        if proxy_type not in {"direct", "reject", "reject-drop", "pass", "dns"}:
            if proxy_type != "wireguard" and not proxy.get("server"):
                errors.append(f"{prefix} ({name or '未命名'}) 缺少 server")
            if proxy_type == "hysteria2":
                ports = proxy.get("ports")
                if ports and not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", str(ports)):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 ports 格式无效: {ports}")
                if not ports and not _is_valid_port(proxy.get("port")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port/ports")
                if not _has_text(proxy.get("password")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少 Hysteria2 password")
                if proxy.get("obfs") not in {None, "", "salamander"}:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 Mihomo Hysteria2 obfs 不受支持: {proxy.get('obfs')}")
                if proxy.get("obfs") and not proxy.get("obfs-password"):
                    errors.append(f"{prefix} ({name or '未命名'}) 启用了 obfs 但缺少 obfs-password")
            elif proxy_type == "tuic":
                if not _is_valid_port(proxy.get("port")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port: {proxy.get('port')}")
                token = proxy.get("token")
                uuid_value = proxy.get("uuid")
                password = proxy.get("password")
                has_token = _has_text(token)
                has_uuid = _has_text(uuid_value)
                has_password = _has_text(password)
                if has_token and (has_uuid or has_password):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC v4 token 不能与 v5 uuid/password 混用")
                elif not has_token:
                    if not has_uuid or not has_password:
                        errors.append(f"{prefix} ({name or '未命名'}) 缺少 TUIC v4 token 或 v5 uuid/password")
                    elif not re.fullmatch(
                        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                        uuid_value.strip(),
                    ):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC uuid 格式无效")
                udp_relay_mode = proxy.get("udp-relay-mode")
                if udp_relay_mode not in {None, "", "native", "quic"}:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC udp-relay-mode 无效: {udp_relay_mode}")
                congestion_controller = proxy.get("congestion-controller")
                if congestion_controller not in {None, "", "cubic", "new_reno", "bbr"}:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC congestion-controller 无效: {congestion_controller}")
                bbr_profile = proxy.get("bbr-profile")
                if bbr_profile not in {None, "", "standard", "conservative", "aggressive"}:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC bbr-profile 无效: {bbr_profile}")
                for field in (
                    "heartbeat-interval",
                    "request-timeout",
                    "max-udp-relay-packet-size",
                    "max-open-streams",
                ):
                    if field in proxy and not _is_non_negative_integer(proxy[field]):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC {field} 必须是非负整数")
                for field in (
                    "udp",
                    "skip-cert-verify",
                    "reduce-rtt",
                    "disable-sni",
                    "fast-open",
                ):
                    if field in proxy and not isinstance(proxy[field], bool):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 TUIC {field} 必须是布尔值")
            elif proxy_type == "anytls":
                if not _is_valid_port(proxy.get("port")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port: {proxy.get('port')}")
                if not _has_text(proxy.get("password")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少 AnyTLS password")
                if proxy.get("reality-opts") or str(proxy.get("security", "")).lower() == "reality":
                    errors.append(f"{prefix} ({name or '未命名'}) 的 Mihomo AnyTLS 不支持 Reality")
                for field in (
                    "idle-session-check-interval",
                    "idle-session-timeout",
                    "min-idle-session",
                ):
                    if field in proxy and not _is_non_negative_integer(proxy[field]):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 AnyTLS {field} 必须是非负整数")
                for field in ("udp", "skip-cert-verify"):
                    if field in proxy and not isinstance(proxy[field], bool):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 AnyTLS {field} 必须是布尔值")
            elif proxy_type == "wireguard":
                if not _is_valid_ip_address(proxy.get("ip"), 4):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 WireGuard IPv4 地址 ip")
                if "ipv6" in proxy and not _is_valid_ip_address(proxy.get("ipv6"), 6):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard ipv6 地址无效")
                if not _is_valid_wireguard_key(proxy.get("private-key")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 WireGuard private-key")

                peers = proxy.get("peers")
                if peers is None:
                    peer_entries = [(proxy, prefix)]
                elif not isinstance(peers, list) or not peers:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard peers 必须是非空列表")
                    peer_entries = []
                else:
                    peer_entries = [
                        (peer, f"{prefix}.peers[{peer_index}]")
                        for peer_index, peer in enumerate(peers, 1)
                    ]

                for peer, peer_prefix in peer_entries:
                    if not isinstance(peer, dict):
                        errors.append(f"{peer_prefix} 必须是对象")
                        continue
                    if not _has_text(peer.get("server")):
                        errors.append(f"{peer_prefix} 缺少 WireGuard server")
                    if not _is_valid_port(peer.get("port")):
                        errors.append(f"{peer_prefix} 缺少有效的 WireGuard port")
                    if not _is_valid_wireguard_key(peer.get("public-key")):
                        errors.append(f"{peer_prefix} 缺少有效的 WireGuard public-key")
                    if "pre-shared-key" in peer and not _is_valid_wireguard_key(peer.get("pre-shared-key")):
                        errors.append(f"{peer_prefix} 的 WireGuard pre-shared-key 无效")
                    if "allowed-ips" in peer and not _is_valid_ip_network_list(peer.get("allowed-ips")):
                        errors.append(f"{peer_prefix} 的 WireGuard allowed-ips 必须是有效的网段列表")
                    if "reserved" in peer and not _is_valid_wireguard_reserved(peer.get("reserved")):
                        errors.append(f"{peer_prefix} 的 WireGuard reserved 必须是三个字节")

                if "mtu" in proxy and not _is_positive_integer(proxy["mtu"]):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard mtu 必须是正整数")
                if "persistent-keepalive" in proxy and (
                    not _is_non_negative_integer(proxy["persistent-keepalive"])
                    or int(proxy["persistent-keepalive"]) > 65535
                ):
                    errors.append(
                        f"{prefix} ({name or '未命名'}) 的 WireGuard persistent-keepalive 必须是 0-65535 的整数"
                    )
                for field in ("udp", "remote-dns-resolve"):
                    if field in proxy and not isinstance(proxy[field], bool):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard {field} 必须是布尔值")
                if "dns" in proxy and not _is_non_empty_string_list(proxy["dns"]):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard dns 必须是非空字符串列表")
                ip_stack = proxy.get("ip-stack")
                if ip_stack is not None:
                    if not isinstance(ip_stack, dict):
                        errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard ip-stack 必须是对象")
                    else:
                        if ip_stack.get("mode") not in {None, "auto", "gvisor", "mips"}:
                            errors.append(f"{prefix} ({name or '未命名'}) 的 WireGuard ip-stack.mode 无效")
                        if ip_stack.get("congestion-controller") not in {
                            None,
                            "cubic",
                            "reno",
                            "bbr",
                            "bbr3",
                        }:
                            errors.append(
                                f"{prefix} ({name or '未命名'}) 的 WireGuard ip-stack.congestion-controller 无效"
                            )
            elif not _is_valid_port(proxy.get("port")):
                errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port: {proxy.get('port')}")
    return errors


def validate_mihomo_config(
    config: Any,
    external_proxy_names: Any = None,
    external_provider_names: Any = None,
    allow_internal_sources: bool = False,
) -> List[str]:
    """Perform static YAML and Mihomo reference checks before publishing config."""
    if not isinstance(config, dict):
        return ["配置根节点必须是 YAML 对象"]

    errors = network_error_messages(validate_network_config(config))
    proxies = config.get("proxies", [])
    errors.extend(validate_proxy_nodes(proxies))
    proxy_names = {
        proxy.get("name") for proxy in proxies
        if isinstance(proxy, dict) and isinstance(proxy.get("name"), str)
    }
    proxy_names.update(str(name) for name in (external_proxy_names or []) if name)

    providers = config.get("proxy-providers", {}) or {}
    if not isinstance(providers, dict):
        errors.append("proxy-providers 必须是对象")
        providers = {}
    provider_names = set(providers)
    provider_names.update(str(name) for name in (external_provider_names or []) if name)
    if allow_internal_sources:
        # Stored ProxyForge templates use this sentinel to mean "inject the
        # persisted custom nodes". It is resolved by build_subscription_config
        # and must remain invalid in the final emitted Mihomo configuration.
        provider_names.add(CUSTOM_NODES_SOURCE)
    for provider_name, provider in providers.items():
        prefix = f"proxy-providers.{provider_name}"
        if not isinstance(provider, dict):
            errors.append(f"{prefix} 必须是对象")
            continue
        provider_type = provider.get("type")
        if provider_type not in {"http", "file", "inline"}:
            errors.append(f"{prefix} 的 type 无效: {provider_type}")
        if provider_type == "http" and not provider.get("url"):
            errors.append(f"{prefix} 缺少 url")
        if provider_type in {"http", "file"} and not provider.get("path"):
            errors.append(f"{prefix} 缺少 path")

    groups = config.get("proxy-groups", []) or []
    if not isinstance(groups, list):
        errors.append("proxy-groups 必须是列表")
        groups = []
    group_names = set()
    for index, group in enumerate(groups, 1):
        if not isinstance(group, dict):
            errors.append(f"proxy-groups[{index}] 必须是对象")
            continue
        name = group.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"proxy-groups[{index}] 缺少有效的 name")
        elif name in group_names:
            errors.append(f"proxy-groups[{index}] 组名重复: {name}")
        else:
            group_names.add(name)

    builtins = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    group_graph = {name: set() for name in group_names}
    for index, group in enumerate(groups, 1):
        if not isinstance(group, dict):
            continue
        name = group.get("name")
        group_type = group.get("type")
        if not group_type:
            errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 缺少 type")
        if group_type in {"url-test", "fallback", "load-balance"} and not group.get("url"):
            errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 的 {group_type} 缺少测速 url")
        refs = group.get("proxies", []) or []
        uses = group.get("use", []) or []
        if not isinstance(refs, list):
            errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 的 proxies 必须是列表")
            refs = []
        if not isinstance(uses, list):
            errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 的 use 必须是列表")
            uses = []
        if not refs and not uses and not group.get("include-all"):
            errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 没有任何 proxies 或 use")
        for provider_name in uses:
            if provider_name not in provider_names:
                errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 引用了不存在的 proxy-provider: {provider_name}")
        for ref in refs:
            if ref not in proxy_names and ref not in group_names and ref not in builtins:
                errors.append(f"proxy-groups[{index}] ({name or '未命名'}) 引用了不存在的代理/组: {ref}")
            if name in group_graph and ref in group_names:
                group_graph[name].add(ref)

    visiting = set()
    visited = set()
    def visit_group(name: str, path: List[str]):
        if name in visiting:
            cycle_start = path.index(name) if name in path else 0
            errors.append(f"代理组存在循环引用: {' -> '.join(path[cycle_start:] + [name])}")
            return
        if name in visited:
            return
        visiting.add(name)
        for child in group_graph.get(name, set()):
            visit_group(child, path + [name])
        visiting.remove(name)
        visited.add(name)
    for group_name in group_graph:
        visit_group(group_name, [])

    rule_providers = config.get("rule-providers", {}) or {}
    if not isinstance(rule_providers, dict):
        errors.append("rule-providers 必须是对象")
        rule_providers = {}
    valid_targets = proxy_names | group_names | builtins
    rules = config.get("rules", []) or []
    if not isinstance(rules, list):
        errors.append("rules 必须是列表")
        rules = []
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, str):
            errors.append(f"rules[{index}] 必须是字符串")
            continue
        parts = [part.strip() for part in rule.split(",")]
        rule_type = parts[0].upper() if parts else ""
        if rule_type == "MATCH":
            target = parts[1] if len(parts) > 1 else ""
        elif rule_type in {"AND", "OR", "NOT", "SUB-RULE"}:
            # Logical rules contain nested commas; leave their grammar to Mihomo.
            continue
        else:
            target = parts[2] if len(parts) > 2 else ""
        if not target:
            errors.append(f"rules[{index}] 缺少目标策略: {rule}")
        elif target not in valid_targets:
            errors.append(f"rules[{index}] 引用了不存在的目标策略 [{target}]: {rule}")
        if rule_type == "RULE-SET":
            provider_name = parts[1] if len(parts) > 1 else ""
            if provider_name not in rule_providers:
                errors.append(f"rules[{index}] 引用了不存在的 rule-provider [{provider_name}]: {rule}")
    return errors


def assert_valid_mihomo_config(config: Any, **kwargs):
    errors = validate_mihomo_config(config, **kwargs)
    if errors:
        raise ConfigValidationError(errors)
