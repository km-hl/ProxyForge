"""Egern native YAML export. Pure conversion; never fetch or mutate inputs."""
import copy
import hashlib
import json
import math
import re
import urllib.parse

from .validation import ConfigValidationError


RULE_TYPES = {
    'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex', 'DOMAIN-WILDCARD': 'domain_wildcard',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr6', 'IP-ASN': 'asn',
    'DST-PORT': 'dest_port', 'NETWORK': 'protocol', 'GEOIP': 'geoip',
}
GROUP_TYPES = {'select': 'select', 'url-test': 'auto_test', 'fallback': 'fallback',
               'load-balance': 'load_balance', 'smart': 'smart'}
PROXY_TYPES = {'ss': 'shadowsocks', 'socks5': 'socks5', 'http': 'http', 'trojan': 'trojan',
               'vmess': 'vmess', 'vless': 'vless', 'hysteria2': 'hysteria2',
               'tuic': 'tuic', 'anytls': 'anytls', 'wireguard': 'wireguard', 'snell': 'snell'}


class UnsupportedNode(ValueError):
    pass


def _mapped(source, mapping):
    return {target: copy.deepcopy(source[key]) for key, target in mapping.items() if key in source}


def convert_proxy(proxy):
    kind = proxy.get('type')
    if kind not in PROXY_TYPES:
        raise UnsupportedNode('protocol')
    if any(proxy.get(key) for key in ('smux', 'reality-opts', 'plugin', 'shadow-tls-password')) and kind not in {'vless', 'vmess', 'ss'}:
        raise UnsupportedNode('transport options')
    output = _mapped(proxy, {'name': 'name', 'server': 'server', 'port': 'port',
                            'tfo': 'tfo', 'dialer-proxy': 'prev_hop'})
    output['port'] = int(output['port'])
    if kind != 'http':
        output['udp_relay'] = proxy.get('udp', True)
    tls = _mapped(proxy, {'servername': 'sni', 'sni': 'sni', 'skip-cert-verify': 'skip_tls_verify',
                          'fingerprint': 'fingerprint_sha256'})
    tls.setdefault('skip_tls_verify', False)
    if kind in {'vless', 'vmess'}:
        output['user_id'] = proxy['uuid']
        if kind == 'vmess':
            if proxy.get('alterId', 0) != 0:
                raise UnsupportedNode('legacy VMess')
            output.update(security=proxy.get('cipher', 'auto'), legacy=False)
        elif proxy.get('flow'):
            if proxy['flow'] != 'xtls-rprx-vision':
                raise UnsupportedNode('flow')
            output['flow'] = proxy['flow']
        network = proxy.get('network', 'tcp')
        reality = proxy.get('reality-opts')
        encrypted = bool(proxy.get('tls') or reality)
        if reality:
            tls['reality'] = _mapped(reality, {'public-key': 'public_key', 'short-id': 'short_id'})
        if network == 'tcp':
            if encrypted:
                output['transport'] = {'tls': tls}
        elif network == 'ws':
            if reality:
                raise UnsupportedNode('Reality WebSocket')
            options = proxy.get('ws-opts') or {}
            if options.get('max-early-data') or options.get('early-data-header-name'):
                raise UnsupportedNode('WebSocket early data')
            transport = {'path': options.get('path', '/')}
            if options.get('headers'):
                transport['headers'] = copy.deepcopy(options['headers'])
            if encrypted:
                transport.update(tls)
            output['transport'] = {'wss' if encrypted else 'ws': transport}
        elif network == 'grpc' and encrypted:
            transport = {**tls, 'service_name': (proxy.get('grpc-opts') or {}).get('grpc-service-name', '')}
            output['transport'] = {'grpc': transport}
        else:
            raise UnsupportedNode('transport')
    elif kind == 'ss':
        output.update(method=proxy['cipher'], password=proxy['password'])
        if proxy.get('plugin'):
            options = proxy.get('plugin-opts') or {}
            if proxy['plugin'] != 'obfs' or options.get('mode') not in {'http', 'tls'}:
                raise UnsupportedNode('Shadowsocks plugin')
            output.update(obfs=options['mode'])
            output.update(_mapped(options, {'host': 'obfs_host', 'uri': 'obfs_uri'}))
    elif kind in {'trojan', 'anytls'}:
        output.update(password=proxy['password'], **tls)
        if proxy.get('network', 'tcp') != 'tcp':
            if kind != 'trojan' or proxy.get('network') != 'ws':
                raise UnsupportedNode('transport')
            options = proxy.get('ws-opts') or {}
            if options.get('max-early-data') or options.get('early-data-header-name'):
                raise UnsupportedNode('WebSocket early data')
            headers = options.get('headers') or {}
            if any(key.lower() != 'host' for key in headers):
                raise UnsupportedNode('Trojan WebSocket headers')
            output['websocket'] = {'path': options.get('path', '/')}
            if headers:
                output['websocket']['host'] = next(iter(headers.values()))
    elif kind == 'hysteria2':
        output.update(auth=proxy['password'], **tls)
        output.update(_mapped(proxy, {'obfs': 'obfs', 'obfs-password': 'obfs_password',
                                     'ports': 'port_hopping', 'hop-interval': 'port_hopping_interval'}))
        if proxy.get('up'):
            match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*(?:Mbps|mbps)?', str(proxy['up']))
            if not match:
                raise UnsupportedNode('bandwidth unit')
            output['bandwidth'] = int(float(match[1]))
    elif kind == 'tuic':
        if proxy.get('token') or proxy.get('disable-sni'):
            raise UnsupportedNode('TUIC version/options')
        output.update(uuid=proxy['uuid'], password=proxy['password'], **tls)
        output.update(_mapped(proxy, {'udp-relay-mode': 'udp_relay_mode', 'alpn': 'alpn'}))
    elif kind in {'socks5', 'http'}:
        output.update(_mapped(proxy, {'username': 'username', 'password': 'password'}))
        if proxy.get('tls'):
            kind = 'socks5_tls' if kind == 'socks5' else 'https'
            output.update(tls)
    elif kind == 'snell':
        output.update(psk=proxy['psk'], version=proxy.get('version', 1))
        output.update(_mapped(proxy.get('obfs-opts') or {}, {'mode': 'obfs', 'host': 'obfs_host'}))
    elif kind == 'wireguard':
        if proxy.get('peers'):
            raise UnsupportedNode('multi-peer WireGuard')
        output.pop('udp_relay', None)
        output.update(_mapped(proxy, {'private-key': 'private_key', 'public-key': 'peer_public_key',
                                     'pre-shared-key': 'preshared_key', 'reserved': 'reserved',
                                     'mtu': 'mtu', 'persistent-keepalive': 'keepalive'}))
        if proxy.get('ip'):
            output['local_ipv4'] = proxy['ip'] if '/' in proxy['ip'] else proxy['ip'] + '/32'
        if proxy.get('ipv6'):
            output['local_ipv6'] = proxy['ipv6'] if '/' in proxy['ipv6'] else proxy['ipv6'] + '/128'
    return {PROXY_TYPES.get(kind, kind): output}


def provider_revision(provider):
    return hashlib.sha256(json.dumps(provider, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def resource_url(base_url, token, kind, value, revision=None, no_resolve=False):
    parameters = {'token': token, 'value': value}
    if revision:
        parameters['revision'] = revision
    if no_resolve:
        parameters['no_resolve'] = 'true'
    return base_url.rstrip('/') + '/egern/ruleset/' + kind + '?' + urllib.parse.urlencode(parameters)


def split_rule(value):
    parts, start, depth = [], 0, 0
    for index, char in enumerate(value):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
        if depth < 0:
            raise ValueError('rule syntax')
    if depth:
        raise ValueError('rule syntax')
    parts.append(value[start:].strip())
    return parts


def rule_condition(parts, *, ruleset=None, depth=0):
    if depth > 12 or not parts:
        raise ValueError('rule nesting')
    kind = parts[0].upper()
    if kind in {'AND', 'OR', 'NOT'}:
        children = parts[1]
        if not children.startswith('(') or not children.endswith(')'):
            raise ValueError('logical rule syntax')
        conditions = []
        for child in split_rule(children[1:-1]):
            if not child.startswith('(') or not child.endswith(')'):
                raise ValueError('logical condition syntax')
            conditions.append(rule_condition(split_rule(child[1:-1]), ruleset=ruleset, depth=depth + 1))
        if not conditions or (kind == 'NOT' and len(conditions) != 1):
            raise ValueError('logical condition count')
        return {kind.lower(): {'match': conditions[0] if kind == 'NOT' else conditions}}
    if len(parts) < 2:
        raise ValueError('rule operand')
    if kind in {'GEOSITE', 'RULE-SET'} or (kind == 'GEOIP' and not re.fullmatch('[A-Za-z]{2}', parts[1])):
        if ruleset is None:
            raise ValueError('nested remote rule set')
        return {'rule_set': {'match': ruleset(kind, parts[1], 'no-resolve' in parts[2:]), 'update_interval': 86400}}
    if kind not in RULE_TYPES:
        raise ValueError('unsupported rule type')
    match = parts[1]
    if kind == 'NETWORK':
        match = match.lower()
    elif kind == 'GEOIP':
        match = match.upper()
    elif kind == 'DST-PORT':
        match = match.replace('/', ',')
    value = {'match': match}
    if 'no-resolve' in parts[2:]:
        if kind not in {'GEOIP', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN'}:
            raise ValueError('no-resolve on non-IP rule')
        value['no_resolve'] = True
    return {RULE_TYPES[kind]: value}


def build_egern_config(config, provider_nodes, base_url, token):
    """Resolve all proxy providers to explicit nodes, retaining group/rule order."""
    converted, omitted, provider_names = [], set(), {}
    all_names = {group['name'] for group in config.get('proxy-groups', [])} | {'DIRECT', 'REJECT'}
    for source, proxies in [(None, config.get('proxies', [])), *provider_nodes.items()]:
        names = []
        for proxy in proxies:
            name = proxy['name']
            if name in all_names:
                raise ConfigValidationError(['Egern 节点/策略名称冲突'])
            all_names.add(name)
            try:
                converted.append(convert_proxy(proxy))
                names.append(name)
            except UnsupportedNode:
                omitted.add(name)
        if source is not None:
            provider_names[source] = names
    if not converted and (config.get('proxies') or provider_nodes):
        raise ConfigValidationError(['没有可供 Egern 使用的兼容节点'])
    groups = []
    for index, group in enumerate(config.get('proxy-groups', []), 1):
        kind = GROUP_TYPES.get(group['type'])
        if kind is None:
            raise ConfigValidationError([f'Egern 不支持代理组类型（第 {index} 组）'])
        policies = ['REJECT' if name in omitted or name == 'REJECT-DROP' else name
                    for name in group.get('proxies', [])]
        for source in group.get('use', []):
            if source not in provider_names:
                raise ConfigValidationError([f'Egern 缺少机场/provider 节点（第 {index} 组）'])
            for name in provider_names[source]:
                if group.get('filter') and not re.search(group['filter'], name):
                    continue
                if group.get('exclude-filter') and re.search(group['exclude-filter'], name):
                    continue
                policies.append(name)
        policies = list(dict.fromkeys(policies)) or ['REJECT']
        output = {'name': group['name'], 'policies': policies}
        output.update(_mapped(group, {'interval': 'interval', 'tolerance': 'tolerance',
                                     'url': 'latency_test_url', 'hidden': 'hidden', 'icon': 'icon'}))
        if 'timeout' in group:
            output['timeout'] = min(60, max(1, math.ceil(group['timeout'] / 1000)))
        if kind == 'load_balance':
            strategy = group.get('strategy', 'consistent-hashing')
            if strategy not in {'consistent-hashing', 'round-robin'}:
                raise ConfigValidationError([f'Egern 不支持负载均衡策略（第 {index} 组）'])
            output['algorithm'] = 'round_robin' if strategy == 'round-robin' else 'hash'
        groups.append({kind: output})

    def ruleset(kind, value, no_resolve=False):
        if kind == 'RULE-SET':
            provider = (config.get('rule-providers') or {}).get(value)
            if provider is None:
                raise ValueError('missing rule provider')
            return resource_url(base_url, token, 'provider', value, provider_revision(provider), no_resolve)
        return resource_url(base_url, token, 'geosite' if kind == 'GEOSITE' else 'geoip', value,
                            no_resolve=no_resolve)

    rules = []
    for index, rule in enumerate(config.get('rules', []), 1):
        try:
            parts = split_rule(rule)
            kind = parts[0].upper()
            target_index = 1 if kind == 'MATCH' else 2
            policy = parts[target_index]
            if any(option != 'no-resolve' for option in parts[target_index + 1:]):
                raise ValueError('unsupported rule option')
            policy = 'REJECT' if policy in omitted or policy == 'REJECT-DROP' else policy
            condition = {'default': {}} if kind == 'MATCH' else rule_condition(
                parts[:target_index] + parts[target_index + 1:], ruleset=ruleset)
            next(iter(condition.values()))['policy'] = policy
            rules.append(condition)
        except (ValueError, IndexError, TypeError):
            raise ConfigValidationError([f'Egern 无法转换第 {index} 条规则；请使用兼容规则']) from None
    result = {'proxies': converted, 'policy_groups': groups, 'rules': rules}
    # A separate native export must never contain raw Mihomo DNS/TUN/ports.
    validate_egern_references(result)
    return result, len(omitted)


def validate_egern_references(config):
    names = {'DIRECT', 'REJECT'}
    for entry in config['proxies'] + config['policy_groups']:
        name = next(iter(entry.values()))['name']
        if name in names:
            raise ConfigValidationError(['Egern 策略名称重复'])
        names.add(name)
    for entry in config['proxies']:
        if next(iter(entry.values())).get('prev_hop', 'DIRECT') not in names:
            raise ConfigValidationError(['Egern 前置代理引用无效'])
    for entry in config['policy_groups']:
        if any(policy not in names for policy in next(iter(entry.values()))['policies']):
            raise ConfigValidationError(['Egern 代理组引用无效'])
    for entry in config['rules']:
        if next(iter(entry.values()))['policy'] not in names:
            raise ConfigValidationError(['Egern 规则策略引用无效'])


def convert_rule_set(content, behavior='classical', file_format='yaml'):
    """Translate Clash rule-provider data, without carrying policy credentials."""
    import yaml
    if file_format not in {'yaml', 'text'} or behavior not in {'domain', 'ipcidr', 'classical'}:
        raise ConfigValidationError(['Egern 规则集仅支持 YAML/text 的 domain/ipcidr/classical'])
    if file_format == 'yaml':
        document = yaml.safe_load(content)
        entries = document.get('payload') if isinstance(document, dict) else None
    else:
        entries = [line.strip() for line in content.splitlines()
                   if line.strip() and not line.lstrip().startswith('#')]
    if not isinstance(entries, list) or not entries or len(entries) > 100000:
        raise ConfigValidationError(['Egern 规则集内容为空、过大或格式无效'])
    result = {}
    for index, entry in enumerate(entries, 1):
        try:
            if not isinstance(entry, str):
                raise ValueError()
            if behavior == 'domain':
                if entry.startswith('+.'):
                    condition = {'domain_suffix': {'match': entry[2:]}}
                elif entry.startswith('.') or '*' in entry or '?' in entry:
                    condition = {'domain_wildcard': {'match': '*' + entry if entry.startswith('.') else entry}}
                else:
                    condition = {'domain': {'match': entry}}
            elif behavior == 'ipcidr':
                condition = {'ip_cidr6' if ':' in entry else 'ip_cidr': {'match': entry}}
            else:
                parts = split_rule(entry)
                # classical rule providers contain conditions, never a policy.
                if len(parts) > 2 and parts[-1] != 'no-resolve':
                    raise ValueError()
                condition = rule_condition(parts)
            kind, value = next(iter(condition.items()))
            # Different no_resolve values cannot be widened by OR-set folding.
            if value.get('no_resolve'):
                result.setdefault('or_set', []).append([condition])
            else:
                result.setdefault(kind + '_set', []).append(value['match'])
        except (ValueError, IndexError, TypeError):
            raise ConfigValidationError([f'Egern 无法转换规则集第 {index} 条条件']) from None
    return result
