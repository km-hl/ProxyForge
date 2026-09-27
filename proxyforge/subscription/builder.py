"""Build subscription/provider documents from explicit inputs; no file I/O."""
import copy
import re
import urllib.parse
from typing import Any, Dict, List

import yaml

from .nodes import CUSTOM_NODES_SOURCE, get_airport_name, decorate_proxy_names
from .validation import ConfigValidationError, assert_valid_mihomo_config


def build_airport_providers(
    airports: List[Any], base_url: str, token: str, reserved_names: Any = None
):
    providers = {}
    source_map = {}
    used_names = set(reserved_names or [])
    for index, item in enumerate(airports):
        source_name = get_airport_name(item, index)
        provider_name = source_name
        suffix = 2
        while provider_name in used_names:
            provider_name = f"{source_name} ({suffix})"
            suffix += 1
        used_names.add(provider_name)
        source_map[source_name.lower()] = provider_name
        provider_url = f"{base_url.rstrip('/')}/provider/{index}?token={urllib.parse.quote(token, safe='')}"
        providers[provider_name] = {
            "type": "http",
            "url": provider_url,
            "path": f"./proxy_providers/proxyforge_{index + 1}.yaml",
            "interval": 14400,
            "health-check": {
                "enable": True,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "timeout": 5000,
                "lazy": True,
            },
            "override": {"additional-prefix": f"{provider_name} | "},
        }
    return providers, source_map


def build_airport_provider_document(proxies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the YAML document served to a Mihomo HTTP proxy-provider."""
    return {"proxies": proxies}


def cleanup_proxy_group_references(
    config: Dict[str, Any],
    valid_proxy_names: Any = None,
    valid_provider_names: Any = None,
    removed_proxy_names: Any = None,
    removed_provider_names: Any = None,
) -> Dict[str, Any]:
    """Remove stale group members without changing routing rule targets."""
    result = {"proxyReferences": [], "providerReferences": [], "total": 0}
    if not isinstance(config, dict):
        return result
    groups = config.get("proxy-groups", [])
    if not isinstance(groups, list):
        return result

    builtins = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    group_names = {
        group.get("name") for group in groups
        if isinstance(group, dict) and isinstance(group.get("name"), str)
    }
    allowed_proxies = None
    if valid_proxy_names is not None:
        # ProxyForge replaces template `proxies` with persisted custom nodes in
        # the final output, so names that only exist in template `proxies` are
        # stale rather than valid references.
        allowed_proxies = builtins | group_names | {
            str(name) for name in valid_proxy_names if name
        }

    configured_providers = config.get("proxy-providers", {}) or {}
    allowed_providers_lower = None
    if valid_provider_names is not None:
        allowed_providers_lower = {
            str(name).lower() for name in valid_provider_names if name
        }
        if isinstance(configured_providers, dict):
            allowed_providers_lower.update(str(name).lower() for name in configured_providers)
        allowed_providers_lower.add(CUSTOM_NODES_SOURCE.lower())

    removed_proxies = {str(name) for name in (removed_proxy_names or []) if name}
    removed_providers_lower = {
        str(name).lower() for name in (removed_provider_names or []) if name
    }

    for group in groups:
        if not isinstance(group, dict):
            continue
        group_name = str(group.get("name", "未命名"))
        refs = group.get("proxies")
        if isinstance(refs, list):
            kept_refs = []
            for ref in refs:
                is_removed = isinstance(ref, str) and ref in removed_proxies
                is_stale = (
                    allowed_proxies is not None
                    and isinstance(ref, str)
                    and ref not in allowed_proxies
                )
                if is_removed or is_stale:
                    result["proxyReferences"].append({"group": group_name, "name": ref})
                elif ref not in kept_refs:
                    kept_refs.append(ref)
            if kept_refs:
                group["proxies"] = kept_refs
            else:
                group.pop("proxies", None)

        uses = group.get("use")
        if isinstance(uses, list):
            kept_uses = []
            for provider_name in uses:
                provider_key = str(provider_name).lower()
                is_removed = provider_key in removed_providers_lower
                is_stale = (
                    allowed_providers_lower is not None
                    and provider_key not in allowed_providers_lower
                )
                if is_removed or is_stale:
                    result["providerReferences"].append({
                        "group": group_name, "name": provider_name
                    })
                elif provider_name not in kept_uses:
                    kept_uses.append(provider_name)
            if kept_uses:
                group["use"] = kept_uses
            else:
                group.pop("use", None)

        default_value = group.get("default")
        if isinstance(default_value, str) and (
            default_value in removed_proxies
            or (allowed_proxies is not None and default_value not in allowed_proxies)
        ):
            group.pop("default", None)

        if not group.get("proxies") and not group.get("use") and not group.get("include-all"):
            group["proxies"] = ["DIRECT"]

    result["total"] = len(result["proxyReferences"]) + len(result["providerReferences"])
    return result


def build_subscription_config(
    template_config: Dict[str, Any],
    custom_proxies: List[Dict[str, Any]],
    airports: List[Any],
    base_url: str,
    token: str,
    managed_references=(),
) -> Dict[str, Any]:
    config = copy.deepcopy(template_config)
    if not isinstance(config, dict):
        raise ConfigValidationError(["模板根节点必须是 YAML 对象"])

    unpublished_managed = set(managed_references) - {
        proxy.get('name') for proxy in custom_proxies if isinstance(proxy, dict)}
    cleanup_proxy_group_references(
        config,
        valid_proxy_names=[
            proxy.get("name") for proxy in custom_proxies
            if isinstance(proxy, dict) and proxy.get("name")
        ] + list(managed_references),
        valid_provider_names=[
            get_airport_name(item, index) for index, item in enumerate(airports)
        ],
    )

    output_proxies, proxy_name_map = decorate_proxy_names(custom_proxies)
    # Resolve withheld managed targets only in this output, never in the saved template.
    # Falling back to DIRECT here would bypass the user's selected proxy route.
    proxy_name_map.update({name: 'REJECT' for name in unpublished_managed})
    config["proxies"] = output_proxies

    existing_providers = config.get("proxy-providers", {}) or {}
    if not isinstance(existing_providers, dict):
        existing_providers = {}
    airport_providers, source_map = build_airport_providers(
        airports, base_url, token, reserved_names=existing_providers
    )
    config["proxy-providers"] = {**existing_providers, **airport_providers}
    if not config["proxy-providers"]:
        config.pop("proxy-providers", None)

    all_airport_provider_names = list(airport_providers)
    custom_names = {proxy.get("name") for proxy in custom_proxies if isinstance(proxy, dict)}
    groups = config.get("proxy-groups", [])
    if isinstance(groups, list):
        for group in groups:
            if not isinstance(group, dict):
                continue
            existing_refs = group.get("proxies", [])
            if not isinstance(existing_refs, list):
                existing_refs = []
            original_use = group.get("use", [])
            if not isinstance(original_use, list):
                original_use = []
            include_all = bool(group.get("include-all"))
            filter_pattern = group.get("filter")

            use_names = []
            include_custom = include_all
            for source in original_use:
                if str(source).lower() == CUSTOM_NODES_SOURCE.lower():
                    include_custom = True
                    continue
                resolved = source_map.get(str(source).lower(), source)
                if resolved not in use_names:
                    use_names.append(resolved)

            # The legacy UI treated a filter without an explicit source as
            # filtering all airports. Preserve that behaviour with providers.
            if include_all or (filter_pattern and not original_use):
                for provider_name in all_airport_provider_names:
                    if provider_name not in use_names:
                        use_names.append(provider_name)
                include_custom = True

            final_refs = []
            for ref in existing_refs:
                mapped_ref = proxy_name_map.get(ref, ref)
                if mapped_ref not in final_refs:
                    final_refs.append(mapped_ref)

            if include_custom:
                compiled_filter = None
                if filter_pattern:
                    try:
                        compiled_filter = re.compile(str(filter_pattern))
                    except re.error as e:
                        raise ConfigValidationError([
                            f"代理组 [{group.get('name', '未命名')}] 的 filter 正则无效: {e}"
                        ])
                for proxy in custom_proxies:
                    original_name = proxy.get("name") if isinstance(proxy, dict) else None
                    if not original_name or original_name not in custom_names:
                        continue
                    if compiled_filter and not compiled_filter.search(str(original_name)):
                        continue
                    output_name = proxy_name_map.get(original_name, original_name)
                    if output_name not in final_refs:
                        final_refs.append(output_name)
                if not final_refs and not use_names and any(
                        not compiled_filter or compiled_filter.search(name) for name in unpublished_managed):
                    final_refs.append('REJECT')

            default_value = proxy_name_map.get(group.get("default"), group.get("default"))
            if default_value in final_refs:
                final_refs.remove(default_value)
                final_refs.insert(0, default_value)

            if final_refs:
                group["proxies"] = final_refs
            else:
                group.pop("proxies", None)
            if use_names:
                group["use"] = use_names
            else:
                group.pop("use", None)
            if not final_refs and not use_names:
                group["proxies"] = ["DIRECT"]
            group.pop("include-all", None)
            group.pop("default", None)

    rules = config.get("rules", [])
    if isinstance(rules, list):
        rewritten_rules = []
        for rule in rules:
            if not isinstance(rule, str):
                rewritten_rules.append(rule)
                continue
            parts = rule.split(",")
            rule_type = parts[0].strip().upper() if parts else ""
            target_index = 1 if rule_type == "MATCH" else 2
            if rule_type not in {"AND", "OR", "NOT", "SUB-RULE"} and len(parts) > target_index:
                target = parts[target_index].strip()
                if target in proxy_name_map:
                    parts[target_index] = parts[target_index].replace(target, proxy_name_map[target], 1)
            rewritten_rules.append(",".join(parts))
        config["rules"] = rewritten_rules

    assert_valid_mihomo_config(config)
    # Verify that the emitted YAML survives a dump/load round trip as the final
    # syntax gate before it reaches Mihomo.
    round_trip = yaml.safe_load(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
    assert_valid_mihomo_config(round_trip)
    return config
