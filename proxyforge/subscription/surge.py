"""Surge INI profile subscription exporter."""
import re
from typing import Any, Dict, List, Optional, Tuple


class UnsupportedSurgeNode(ValueError):
    pass


def convert_proxy_to_surge(proxy: Dict[str, Any]) -> str:
    kind = str(proxy.get('type') or '').lower()
    name = str(proxy.get('name') or '').replace(',', '_').replace('=', '_')
    server = str(proxy.get('server') or '')
    port = int(proxy.get('port') or 0)
    if not name or not server or not 1 <= port <= 65535:
        raise UnsupportedSurgeNode('invalid node endpoint')

    common = []
    if proxy.get('tfo'):
        common.append('tfo=true')
    if proxy.get('skip-cert-verify'):
        common.append('skip-cert-verify=true')
    sni = proxy.get('servername') or proxy.get('sni')
    if sni:
        common.append(f'sni={sni}')

    if kind == 'ss':
        params = [f'{name} = ss', server, str(port), f"encrypt-method={proxy['cipher']}", f"password={proxy['password']}"]
        if proxy.get('udp', True):
            params.append('udp-relay=true')
        return ', '.join(params + common)

    if kind == 'trojan':
        params = [f'{name} = trojan', server, str(port), f"password={proxy['password']}"]
        if str(proxy.get('network', 'tcp')).lower() == 'ws':
            opts = proxy.get('ws-opts') or {}
            params.extend(['ws=true', f"ws-path={opts.get('path', '/')}"])
        return ', '.join(params + common)

    if kind == 'vmess':
        params = [f'{name} = vmess', server, str(port), f"username={proxy['uuid']}"]
        if proxy.get('tls'):
            params.append('tls=true')
        if str(proxy.get('network', 'tcp')).lower() == 'ws':
            opts = proxy.get('ws-opts') or {}
            params.extend(['ws=true', f"ws-path={opts.get('path', '/')}"])
            host = (opts.get('headers') or {}).get('Host')
            if host:
                params.append(f'ws-headers=Host:{host}')
        return ', '.join(params + common)

    if kind == 'vless':
        if proxy.get('reality-opts'):
            raise UnsupportedSurgeNode('Surge does not natively support VLESS Reality in standard INI')
        params = [f'{name} = vless', server, str(port), f"username={proxy['uuid']}"]
        if proxy.get('tls'):
            params.append('tls=true')
        if str(proxy.get('network', 'tcp')).lower() == 'ws':
            opts = proxy.get('ws-opts') or {}
            params.extend(['ws=true', f"ws-path={opts.get('path', '/')}"])
        return ', '.join(params + common)

    if kind == 'hysteria2':
        params = [f'{name} = hysteria2', server, str(port), f"password={proxy['password']}"]
        return ', '.join(params + common)

    if kind == 'tuic':
        params = [f'{name} = tuic', server, str(port), f"uuid={proxy.get('uuid', '')}", f"password={proxy.get('password', '')}"]
        return ', '.join(params + common)

    if kind == 'snell':
        params = [f'{name} = snell', server, str(port), f"psk={proxy['psk']}"]
        if proxy.get('version'):
            params.append(f"version={proxy['version']}")
        return ', '.join(params + common)

    if kind in ('socks5', 'socks'):
        params = [f'{name} = socks5', server, str(port)]
        if proxy.get('username'):
            params.append(f"username={proxy['username']}")
        if proxy.get('password'):
            params.append(f"password={proxy['password']}")
        if proxy.get('tls'):
            params.append('tls=true')
        return ', '.join(params + common)

    if kind == 'http':
        scheme = 'https' if proxy.get('tls') else 'http'
        params = [f'{name} = {scheme}', server, str(port)]
        if proxy.get('username'):
            params.append(f"username={proxy['username']}")
        if proxy.get('password'):
            params.append(f"password={proxy['password']}")
        return ', '.join(params + common)

    raise UnsupportedSurgeNode(f'unsupported protocol {kind}')


def build_surge_config(
    config: Dict[str, Any],
    provider_nodes: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[str, int]:
    """Compile Mihomo config + provider nodes into a Surge INI profile string."""
    provider_nodes = provider_nodes or {}
    proxy_lines: List[str] = []
    skipped = 0
    seen = {'DIRECT', 'REJECT'}
    provider_names: Dict[str, List[str]] = {}

    for source, proxies in [(None, config.get('proxies', [])), *provider_nodes.items()]:
        bucket: List[str] = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            raw_name = str(proxy.get('name') or '')
            safe_name = raw_name.replace(',', '_').replace('=', '_')
            if not safe_name or safe_name in seen:
                continue
            try:
                proxy_lines.append(convert_proxy_to_surge(proxy))
                seen.add(safe_name)
                bucket.append(safe_name)
            except UnsupportedSurgeNode:
                skipped += 1
        if source is not None:
            provider_names[source] = bucket

    group_lines: List[str] = []
    valid_groups = set()
    for group in config.get('proxy-groups', []):
        if isinstance(group, dict) and group.get('name'):
            valid_groups.add(str(group['name']).replace(',', '_').replace('=', '_'))

    first_group = ''
    for group in config.get('proxy-groups', []):
        if not isinstance(group, dict) or not group.get('name'):
            continue
        g_name = str(group['name']).replace(',', '_').replace('=', '_')
        if not first_group:
            first_group = g_name
        g_type = str(group.get('type') or 'select').lower()
        surge_type = {'select': 'select', 'url-test': 'url-test', 'fallback': 'fallback',
                      'load-balance': 'load-balance', 'smart': 'smart'}.get(g_type, 'select')
        members: List[str] = []
        for ref in group.get('proxies', []) or []:
            clean_ref = str(ref).replace(',', '_').replace('=', '_')
            if clean_ref in seen or clean_ref in valid_groups:
                if clean_ref not in members:
                    members.append(clean_ref)
        for src in group.get('use', []) or []:
            for cand in provider_names.get(src, []):
                if group.get('filter') and not re.search(str(group['filter']), cand):
                    continue
                if group.get('exclude-filter') and re.search(str(group['exclude-filter']), cand):
                    continue
                if cand not in members:
                    members.append(cand)
        if not members:
            members = ['DIRECT']
        extras = ''
        if surge_type in ('url-test', 'fallback'):
            extras = f", url={group.get('url', 'https://www.gstatic.com/generate_204')}, interval={int(group.get('interval') or 300)}"
        group_lines.append(f"{g_name} = {surge_type}, {', '.join(members)}{extras}")
        seen.add(g_name)

    rule_lines: List[str] = []
    final_line = f'FINAL,{first_group or "DIRECT"}'
    for raw_rule in config.get('rules', []) or []:
        if not isinstance(raw_rule, str):
            continue
        parts = [p.strip() for p in raw_rule.split(',')]
        if not parts:
            continue
        kind = parts[0].upper()
        if kind == 'MATCH':
            policy = parts[1] if len(parts) > 1 else 'DIRECT'
            final_line = f'FINAL,{policy}'
            continue
        if len(parts) >= 3 and kind in {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'DST-PORT', 'PROCESS-NAME'}:
            policy = parts[2].replace(',', '_').replace('=', '_')
            if policy not in seen:
                policy = 'DIRECT'
            no_resolve = ',no-resolve' if 'no-resolve' in parts[3:] else ''
            rule_lines.append(f'{kind},{parts[1]},{policy}{no_resolve}')

    sections = [
        '[General]',
        'loglevel = notify',
        'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local',
        'dns-server = 223.5.5.5, 1.1.1.1',
        'ipv6 = true',
        '',
        '[Proxy]',
        'DIRECT = direct',
        'REJECT = reject',
        *proxy_lines,
        '',
        '[Proxy Group]',
        *group_lines,
        '',
        '[Rule]',
        *rule_lines,
        final_line,
    ]
    return '\n'.join(sections) + '\n', skipped
