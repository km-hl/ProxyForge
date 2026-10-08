"""Bounded, DNS-pinned source loading for native Egern export resources."""
import copy
import re
import threading
import time

from cachetools import TTLCache
import yaml

from proxyforge.security.network_security import safe_get
from .egern import convert_rule_set, provider_revision
from .nodes import decorate_proxy_names, get_airport_name
from .builder import build_airport_providers
from .validation import ConfigValidationError, validate_proxy_nodes


_cache = TTLCache(maxsize=32 * 1024 * 1024, ttl=14400, getsizeof=lambda value: len(value.encode('utf-8')))
_lock = threading.RLock()
_slots = threading.BoundedSemaphore(4)


def load_rule_resource(kind, value, providers, revision=None, no_resolve=False):
    if kind in {'geosite', 'geoip'}:
        if not re.fullmatch(r'[a-z0-9][a-z0-9_@!.\-]{0,127}', value) or '..' in value:
            raise ConfigValidationError(['Egern 地理规则类别无效'])
        category = 'private' if kind == 'geoip' and value == 'lan' else value
        url = f'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/{kind}/{category}.yaml'
        behavior, file_format = ('domain' if kind == 'geosite' else 'ipcidr'), 'yaml'
    elif kind == 'provider':
        provider = providers.get(value)
        if not provider or revision != provider_revision(provider):
            raise ConfigValidationError(['规则集已变更，请更新 Egern 配置'])
        if provider.get('type') != 'http':
            raise ConfigValidationError(['Egern 规则集仅支持 HTTP 来源'])
        behavior, file_format = provider.get('behavior', 'classical'), provider.get('format', 'yaml')
        if file_format == 'mrs':
            raise ConfigValidationError(['Egern 暂不转换 MRS；请改用 YAML/text 规则来源'])
        url = provider.get('url')
    else:
        raise ConfigValidationError(['Egern 规则集类型无效'])
    key = (url, behavior, file_format, no_resolve)
    with _lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached
    if not _slots.acquire(blocking=False):
        raise ConfigValidationError(['规则集请求繁忙，请稍后重试'])
    try:
        response = safe_get(url, timeout=15, total_timeout=30, max_response_bytes=8 * 1024 * 1024)
        response.raise_for_status()
        result = convert_rule_set(response.content.decode('utf-8-sig'), behavior, file_format)
        if no_resolve:
            result['no_resolve'] = True
        content = yaml.safe_dump(result, allow_unicode=True, sort_keys=False)
        with _lock:
            _cache[key] = content
        return content
    finally:
        _slots.release()


def resolve_provider_nodes(config, airports, airport_proxies, base_url, token, *,
                           template_providers=None, ca_bundle=None):
    """Expand the exact provider snapshot used by the Mihomo builder."""
    providers = config.get('proxy-providers') or {}
    generated, _ = build_airport_providers(airports, base_url, token, reserved_names=template_providers or {})
    result = {}
    for index, (name, _) in enumerate(generated.items()):
        source = get_airport_name(airports[index], index).lower()
        proxies = [proxy for proxy in airport_proxies if str(proxy.get('_airport_name', '')).lower() == source]
        decorated, _ = decorate_proxy_names(proxies)
        result[name] = [{**proxy, 'name': name + ' | ' + proxy['name']} for proxy in decorated]
    used = {name for group in config.get('proxy-groups', []) for name in group.get('use', [])}
    deadline = time.monotonic() + 60
    for name in used - result.keys():
        provider = providers[name]
        if provider.get('type') == 'inline':
            proxies = copy.deepcopy(provider.get('payload', []))
        elif provider.get('type') == 'http':
            response = safe_get(provider['url'], timeout=15, total_timeout=30,
                                max_response_bytes=8 * 1024 * 1024, ca_bundle=ca_bundle, deadline=deadline)
            response.raise_for_status()
            document = yaml.safe_load(response.content.decode('utf-8-sig'))
            proxies = document.get('proxies') if isinstance(document, dict) else None
        else:
            raise ConfigValidationError(['Egern 暂不展开本地文件 proxy-provider'])
        if not isinstance(proxies, list) or validate_proxy_nodes(proxies):
            raise ConfigValidationError(['Egern proxy-provider 内容无效'])
        override = provider.get('override') or {}
        if set(override) - {'additional-prefix', 'additional-suffix', 'udp', 'tfo', 'skip-cert-verify', 'dialer-proxy'}:
            raise ConfigValidationError(['Egern proxy-provider override 含未支持字段'])
        result[name] = []
        for proxy in proxies:
            updated = {**copy.deepcopy(proxy), **{k: v for k, v in override.items() if not k.startswith('additional-')}}
            updated['name'] = override.get('additional-prefix', '') + proxy['name'] + override.get('additional-suffix', '')
            result[name].append(updated)
    return result
