"""Sing-box Client JSON subscription exporter (sing-box 1.12+)."""
import re
from typing import Any, Dict, List, Optional, Tuple


class UnsupportedSingboxNode(ValueError):
    pass


def _tls_block(proxy: Dict[str, Any], *, sni_default: str = '') -> Optional[Dict[str, Any]]:
    reality = proxy.get('reality-opts')
    tls_enabled = bool(proxy.get('tls')) or bool(reality) or proxy.get('type') in {'trojan', 'hysteria2', 'tuic', 'anytls'}
    if not tls_enabled:
        return None
    tls: Dict[str, Any] = {'enabled': True}
    sni = proxy.get('servername') or proxy.get('sni') or sni_default
    if sni:
        tls['server_name'] = str(sni)
    if proxy.get('skip-cert-verify'):
        tls['insecure'] = True
    alpn = proxy.get('alpn')
    if isinstance(alpn, list) and alpn:
        tls['alpn'] = [str(item) for item in alpn]
    fp = proxy.get('client-fingerprint') or proxy.get('fingerprint')
    if fp and reality:
        tls['utls'] = {'enabled': True, 'fingerprint': str(fp)}
    elif fp:
        tls['utls'] = {'enabled': True, 'fingerprint': str(fp)}
    if isinstance(reality, dict) and reality.get('public-key'):
        rel = {'enabled': True, 'public_key': str(reality['public-key'])}
        if reality.get('short-id'):
            rel['short_id'] = str(reality['short-id'])
        tls['reality'] = rel
    return tls


def _transport_block(proxy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    network = str(proxy.get('network', 'tcp')).lower()
    if network in ('', 'tcp'):
        return None
    if network == 'ws':
        opts = proxy.get('ws-opts') or {}
        block: Dict[str, Any] = {'type': 'ws', 'path': str(opts.get('path') or '/')}
        if isinstance(opts.get('headers'), dict) and opts['headers']:
            block['headers'] = {str(k): str(v) for k, v in opts['headers'].items()}
        return block
    if network == 'grpc':
        opts = proxy.get('grpc-opts') or {}
        return {'type': 'grpc', 'service_name': str(opts.get('grpc-service-name') or '')}
    if network == 'h2':
        opts = proxy.get('h2-opts') or {}
        block = {'type': 'http', 'path': str(opts.get('path') or '/')}
        if opts.get('host'):
            block['host'] = list(opts['host'])
        return block
    raise UnsupportedSingboxNode(f'unsupported transport {network}')


def convert_proxy_to_singbox(proxy: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(proxy.get('type') or '').lower()
    tag = str(proxy.get('name') or '')
    server = str(proxy.get('server') or '')
    port = int(proxy.get('port') or 0)
    if not tag or not server or not 1 <= port <= 65535:
        raise UnsupportedSingboxNode('invalid node endpoint')

    if kind == 'ss':
        out: Dict[str, Any] = {
            'type': 'shadowsocks',
            'tag': tag,
            'server': server,
            'server_port': port,
            'method': str(proxy.get('cipher') or ''),
            'password': str(proxy.get('password') or ''),
        }
        return out

    if kind == 'vless':
        out = {
            'type': 'vless',
            'tag': tag,
            'server': server,
            'server_port': port,
            'uuid': str(proxy.get('uuid') or ''),
        }
        if proxy.get('flow'):
            out['flow'] = str(proxy['flow'])
        tls = _tls_block(proxy)
        if tls:
            out['tls'] = tls
        transport = _transport_block(proxy)
        if transport:
            out['transport'] = transport
        return out

    if kind == 'vmess':
        out = {
            'type': 'vmess',
            'tag': tag,
            'server': server,
            'server_port': port,
            'uuid': str(proxy.get('uuid') or ''),
            'security': str(proxy.get('cipher') or 'auto'),
            'alter_id': int(proxy.get('alterId') or 0),
        }
        tls = _tls_block(proxy)
        if tls:
            out['tls'] = tls
        transport = _transport_block(proxy)
        if transport:
            out['transport'] = transport
        return out

    if kind == 'trojan':
        out = {
            'type': 'trojan',
            'tag': tag,
            'server': server,
            'server_port': port,
            'password': str(proxy.get('password') or ''),
        }
        tls = _tls_block(proxy, sni_default=server)
        if tls:
            out['tls'] = tls
        transport = _transport_block(proxy)
        if transport:
            out['transport'] = transport
        return out

    if kind == 'hysteria2':
        out = {
            'type': 'hysteria2',
            'tag': tag,
            'server': server,
            'server_port': port,
            'password': str(proxy.get('password') or ''),
        }
        if proxy.get('ports'):
            out['server_ports'] = [
                p.strip().replace('-', ':')
                for p in str(proxy['ports']).split(',')
                if p.strip()
            ]
        if proxy.get('hop-interval'):
            out['hop_interval'] = f"{int(proxy['hop-interval'])}s"
        if proxy.get('up'):
            out['up_mbps'] = int(proxy['up'])
        if proxy.get('down'):
            out['down_mbps'] = int(proxy['down'])
        if proxy.get('obfs') == 'salamander' and proxy.get('obfs-password'):
            out['obfs'] = {'type': 'salamander', 'password': str(proxy['obfs-password'])}
        tls = _tls_block(proxy, sni_default=server)
        if tls:
            out['tls'] = tls
        return out

    if kind == 'tuic':
        out = {
            'type': 'tuic',
            'tag': tag,
            'server': server,
            'server_port': port,
            'uuid': str(proxy.get('uuid') or ''),
            'password': str(proxy.get('password') or ''),
            'congestion_control': str(proxy.get('congestion-controller') or 'bbr'),
        }
        tls = _tls_block(proxy, sni_default=server)
        if tls:
            out['tls'] = tls
        return out

    if kind == 'anytls':
        out = {
            'type': 'anytls',
            'tag': tag,
            'server': server,
            'server_port': port,
            'password': str(proxy.get('password') or ''),
        }
        tls = _tls_block(proxy, sni_default=server)
        if tls:
            out['tls'] = tls
        return out

    if kind in ('socks5', 'socks'):
        out = {'type': 'socks', 'tag': tag, 'server': server, 'server_port': port}
        if proxy.get('username'):
            out['username'] = str(proxy['username'])
        if proxy.get('password'):
            out['password'] = str(proxy['password'])
        return out

    if kind == 'http':
        out = {'type': 'http', 'tag': tag, 'server': server, 'server_port': port}
        if proxy.get('username'):
            out['username'] = str(proxy['username'])
        if proxy.get('password'):
            out['password'] = str(proxy['password'])
        tls = _tls_block(proxy)
        if tls:
            out['tls'] = tls
        return out

    raise UnsupportedSingboxNode(f'unsupported protocol {kind}')


_GEO_TAG_RE = re.compile(r'[a-z0-9][a-z0-9_@!.\-]{0,127}')


def _translate_rule_to_singbox(rule_str: str) -> Optional[Dict[str, Any]]:
    parts = [p.strip() for p in str(rule_str).split(',')]
    if not parts:
        return None
    kind = parts[0].upper()
    if kind == 'MATCH':
        target = parts[1] if len(parts) > 1 else 'DIRECT'
        return {'__final__': 'direct' if target == 'DIRECT' else ('__reject__' if target in ('REJECT', 'REJECT-DROP') else target)}
    if len(parts) < 3:
        return None
    operand, target = parts[1], parts[2]
    action_fields = {'action': 'reject'} if target in ('REJECT', 'REJECT-DROP') else {
        'outbound': 'direct' if target == 'DIRECT' else target,
    }
    if kind == 'DOMAIN':
        return {'domain': [operand], **action_fields}
    if kind == 'DOMAIN-SUFFIX':
        return {'domain_suffix': [operand], **action_fields}
    if kind == 'DOMAIN-KEYWORD':
        return {'domain_keyword': [operand], **action_fields}
    if kind == 'DOMAIN-REGEX':
        return {'domain_regex': [operand], **action_fields}
    if kind == 'IP-CIDR':
        return {'ip_cidr': [operand], **action_fields}
    if kind == 'IP-CIDR6':
        return {'ip_cidr': [operand], **action_fields}
    if kind == 'DST-PORT':
        return {'port': [int(operand)] if operand.isdigit() else [], **action_fields}
    if kind == 'PROCESS-NAME':
        return {'process_name': [operand], **action_fields}
    if kind in ('GEOSITE', 'GEOIP'):
        tag = operand.strip().lower()
        category = 'private' if (kind == 'GEOIP' and tag == 'lan') else tag
        if not _GEO_TAG_RE.fullmatch(category) or '..' in category:
            return None
        geo_kind = 'geosite' if kind == 'GEOSITE' else 'geoip'
        rs_tag = f'{geo_kind}-{category}'
        return {
            'rule_set': [rs_tag],
            '__rule_set_meta__': {
                'tag': rs_tag,
                'type': 'remote',
                'format': 'binary',
                'url': f'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/{geo_kind}/{category}.srs',
            },
            **action_fields,
        }
    return None


def build_singbox_config(
    config: Dict[str, Any],
    provider_nodes: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[Dict[str, Any], int]:
    """Compile Mihomo config + provider nodes into a complete Sing-box Client JSON dict."""
    provider_nodes = provider_nodes or {}
    outbounds: List[Dict[str, Any]] = []
    skipped = 0
    seen_tags = {'direct'}
    node_tags: List[str] = []
    provider_tags: Dict[str, List[str]] = {}

    for source, proxies in [(None, config.get('proxies', [])), *provider_nodes.items()]:
        bucket: List[str] = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            name = str(proxy.get('name') or '')
            if not name or name in seen_tags:
                continue
            try:
                converted = convert_proxy_to_singbox(proxy)
                seen_tags.add(name)
                outbounds.append(converted)
                bucket.append(name)
                if source is None:
                    node_tags.append(name)
            except UnsupportedSingboxNode:
                skipped += 1
        if source is not None:
            provider_tags[source] = bucket

    group_outbounds: List[Dict[str, Any]] = []
    valid_group_names = {str(g.get('name')) for g in config.get('proxy-groups', []) if isinstance(g, dict) and g.get('name')}
    for group in config.get('proxy-groups', []):
        if not isinstance(group, dict) or not group.get('name'):
            continue
        g_name = str(group['name'])
        g_type = str(group.get('type') or 'select').lower()
        members: List[str] = []
        for ref in group.get('proxies', []) or []:
            mapped = 'direct' if ref == 'DIRECT' else ref
            if mapped in seen_tags or mapped in valid_group_names:
                if mapped not in members:
                    members.append(mapped)
        for src in group.get('use', []) or []:
            for candidate in provider_tags.get(src, []):
                if group.get('filter') and not re.search(str(group['filter']), candidate):
                    continue
                if group.get('exclude-filter') and re.search(str(group['exclude-filter']), candidate):
                    continue
                if candidate not in members:
                    members.append(candidate)
        if not members:
            members = ['direct']
        sb_type = 'selector' if g_type == 'select' else 'urltest'
        grp_obj: Dict[str, Any] = {'type': sb_type, 'tag': g_name, 'outbounds': members}
        if sb_type == 'urltest':
            grp_obj['url'] = str(group.get('url') or 'https://www.gstatic.com/generate_204')
            grp_obj['interval'] = f"{int(group.get('interval') or 300)}s"
        group_outbounds.append(grp_obj)
        seen_tags.add(g_name)

    default_final = group_outbounds[0]['tag'] if group_outbounds else (node_tags[0] if node_tags else 'direct')
    route_rules: List[Dict[str, Any]] = [
        {'action': 'sniff'},
        {'protocol': 'dns', 'action': 'hijack-dns'},
        {'ip_is_private': True, 'outbound': 'direct'},
    ]
    final_outbound = default_final
    rule_sets_by_tag: Dict[str, Dict[str, Any]] = {}
    for raw_rule in config.get('rules', []) or []:
        translated = _translate_rule_to_singbox(raw_rule) if isinstance(raw_rule, str) else None
        if not translated:
            continue
        if '__final__' in translated:
            target = translated['__final__']
            final_outbound = 'direct' if target == '__reject__' else target
            continue
        rs_meta = translated.pop('__rule_set_meta__', None)
        target_ob = translated.get('outbound')
        if target_ob and target_ob not in seen_tags:
            continue
        if 'port' in translated and not translated['port']:
            continue
        if rs_meta and rs_meta['tag'] not in rule_sets_by_tag:
            entry = dict(rs_meta)
            if default_final and default_final != 'direct':
                entry['download_detour'] = default_final
            rule_sets_by_tag[rs_meta['tag']] = entry
        route_rules.append(translated)

    outbounds_final = group_outbounds + outbounds + [{'type': 'direct', 'tag': 'direct'}]
    dns_cfg = config.get('dns') if isinstance(config.get('dns'), dict) else {}
    tun_cfg = config.get('tun') if isinstance(config.get('tun'), dict) else {}
    ipv6_enabled = config.get('ipv6') is not False and dns_cfg.get('ipv6') is not False

    remote_srv = '1.1.1.1'
    for candidate_list in (dns_cfg.get('fallback'), dns_cfg.get('nameserver')):
        if isinstance(candidate_list, list) and candidate_list:
            first_ns = str(candidate_list[0]).strip()
            if first_ns:
                remote_srv = re.sub(r'^[a-z0-9+]+://', '', first_ns).split('/')[0] or '1.1.1.1'
                break

    local_srv_entry: Dict[str, Any] = {'type': 'local', 'tag': 'local'}
    for local_list in (dns_cfg.get('default-nameserver'), dns_cfg.get('proxy-server-nameserver')):
        if isinstance(local_list, list) and local_list:
            first_local = str(local_list[0]).strip()
            if first_local:
                clean_local = re.sub(r'^[a-z0-9+]+://', '', first_local).split('/')[0]
                if clean_local:
                    local_srv_entry = {'type': 'udp', 'tag': 'local', 'server': clean_local}
                break

    dns_rules: List[Dict[str, Any]] = [{'clash_mode': 'direct', 'server': 'local'}]
    domestic_rule_sets = [tag for tag in ('geosite-private', 'geosite-cn') if tag in rule_sets_by_tag]
    if domestic_rule_sets:
        dns_rules.append({'rule_set': domestic_rule_sets, 'server': 'local'})

    dns_section: Dict[str, Any] = {
        'servers': [
            {
                'type': 'https',
                'tag': 'remote',
                'server': remote_srv,
                'detour': default_final if default_final != 'direct' else 'direct',
            },
            local_srv_entry,
        ],
        'rules': dns_rules,
        'final': 'remote',
    }
    if not ipv6_enabled:
        dns_section['strategy'] = 'ipv4_only'
    if str(dns_cfg.get('enhanced-mode') or '').lower() == 'fake-ip':
        inet4_range = str(dns_cfg.get('fake-ip-range') or '198.18.0.1/16')
        fakeip_cfg: Dict[str, Any] = {'enabled': True, 'inet4_range': inet4_range}
        if ipv6_enabled and dns_cfg.get('fake-ip-range6'):
            fakeip_cfg['inet6_range'] = str(dns_cfg['fake-ip-range6'])
        dns_section['fakeip'] = fakeip_cfg

    inbounds_list: List[Dict[str, Any]] = []
    if tun_cfg.get('enable') is not False:
        tun_addrs = ['172.19.0.1/30']
        if ipv6_enabled:
            tun_addrs.append('fdfe:dcba:9876::1/126')
        tun_in: Dict[str, Any] = {
            'type': 'tun',
            'tag': 'tun-in',
            'address': tun_addrs if tun_cfg else ['172.19.0.1/30'],
            'auto_route': bool(tun_cfg.get('auto-route', True)),
            'strict_route': bool(tun_cfg.get('strict-route', True)),
        }
        if tun_cfg.get('stack'):
            tun_in['stack'] = str(tun_cfg['stack']).lower()
        if tun_cfg.get('mtu'):
            try:
                tun_in['mtu'] = int(tun_cfg['mtu'])
            except (TypeError, ValueError):
                pass
        inbounds_list.append(tun_in)
    inbounds_list.append({'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 2080})

    route_section: Dict[str, Any] = {
        'rules': route_rules,
        'auto_detect_interface': True,
        'final': final_outbound if final_outbound in seen_tags else 'direct',
    }
    if rule_sets_by_tag:
        route_section['rule_set'] = list(rule_sets_by_tag.values())

    profile = {
        'log': {'level': 'info', 'timestamp': True},
        'dns': dns_section,
        'inbounds': inbounds_list,
        'outbounds': outbounds_final,
        'route': route_section,
    }
    return profile, skipped
