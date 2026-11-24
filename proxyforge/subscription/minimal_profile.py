"""Minimal multi-user subscription profile builder, UA detector, and status notice nodes."""
import copy
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .nodes import apply_prefer_relay, decorate_proxy_names
from .validation import assert_valid_mihomo_config

_SINGBOX_UA_RE = re.compile(r'(?:sing-?box|\bsfa\b|\bsfi\b|\bsfm\b|hiddify|nekobox)', re.IGNORECASE)
_URI_UA_RE = re.compile(r'(?:v2ray|shadowrocket|quantumult|loon|streisand|foxray|nekoray|v2box)', re.IGNORECASE)
_MIHOMO_UA_RE = re.compile(r'(?:clash|mihomo|stash|flclash|verge|metacube)', re.IGNORECASE)

_NOTICE_PROXY_DEFAULTS = {
    'type': 'ss',
    'server': '127.0.0.1',
    'port': 1,
    'cipher': 'aes-128-gcm',
    'password': 'notice',
    'udp': False,
}

MINIMAL_SPLIT_RULES = [
    'GEOIP,LAN,DIRECT,no-resolve',
    'GEOSITE,private,DIRECT',
    'GEOSITE,cn,DIRECT',
    'GEOIP,cn,DIRECT,no-resolve',
    'MATCH,节点选择',
]

MINIMAL_ANTI_LEAK_DNS = {
    'enable': True,
    'ipv6': True,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter': [
        '*.lan',
        '*.local',
        'geosite:private',
        'geosite:cn',
        'localhost.ptlogin2.qq.com',
        '+.srv.nintendo.net',
        '+.stun.playstation.net',
    ],
    'respect-rules': True,
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query',
    ],
    'nameserver': [
        'https://1.1.1.1/dns-query',
        'https://8.8.8.8/dns-query',
    ],
    'nameserver-policy': {
        'geosite:private,cn': [
            'https://dns.alidns.com/dns-query',
            'https://doh.pub/dns-query',
        ],
    },
}

MINIMAL_SNIFFER = {
    'enable': True,
    'parse-pure-ip': True,
    'sniff': {
        'HTTP': {'ports': [80, '8080-8880'], 'override-destination': True},
        'TLS': {'ports': [443, 8443]},
        'QUIC': {'ports': [443, 8443]},
    },
}


def detect_target_from_user_agent(user_agent: str) -> str:
    """Detect subscription target format from HTTP User-Agent header."""
    ua = str(user_agent or '').strip()
    if not ua:
        return 'mihomo'
    lower = ua.lower()
    if 'egern' in lower:
        return 'egern'
    if 'surge' in lower:
        return 'surge'
    if _SINGBOX_UA_RE.search(ua):
        return 'singbox'
    if _MIHOMO_UA_RE.search(ua):
        return 'mihomo'
    if _URI_UA_RE.search(ua):
        return 'uri'
    return 'mihomo'


def format_notice_bytes(num_bytes: int) -> str:
    """Format bytes compactly with no space before unit (prevents GB -> UK flag regex collisions)."""
    val = max(0, int(num_bytes or 0))
    if val < 1024:
        return f'{val}B'
    units = ('KB', 'MB', 'GB', 'TB', 'PB')
    size = float(val)
    for unit in units:
        size /= 1024.0
        if size < 1024.0 or unit == units[-1]:
            return f'{size:.2f}{unit}'
    return f'{val}B'


def build_info_notices(user: Dict[str, Any]) -> List[str]:
    """Build top-of-list expiry and remaining quota placeholder labels."""
    expire_at = float(user.get('expire_at') or 0)
    if expire_at > 0:
        dt = datetime.fromtimestamp(expire_at, tz=timezone.utc)
        exp_label = f"⏳ 到期 {dt.strftime('%Y-%m-%d')}"
    else:
        exp_label = '⏳ 长期有效'

    quota = max(0, int(user.get('quota_bytes') or 0))
    used = max(0, int(user.get('upload_bytes') or 0)) + max(0, int(user.get('download_bytes') or 0))
    if quota > 0:
        rem = max(0, quota - used)
        quota_label = f'📊 剩余 {format_notice_bytes(rem)}/{format_notice_bytes(quota)}'
    else:
        quota_label = f'📊 已用 {format_notice_bytes(used)}/不限'
    return [exp_label, quota_label]


def build_disabled_notice(reason: str) -> str:
    if reason == 'expired':
        return '⚠️ 订阅已过期'
    if reason == 'quota_exceeded':
        return '⚠️ 流量已用尽'
    return '⚠️ 订阅已停用'


def make_notice_proxy(name: str) -> Dict[str, Any]:
    return {**_NOTICE_PROXY_DEFAULTS, 'name': str(name)}


def proxy_node_key(proxy: Dict[str, Any]) -> str:
    """Compute canonical node authorization key matching `/api/sub-users/available-nodes`."""
    managed = proxy.get('_managed_by')
    if isinstance(managed, dict):
        mtype = managed.get('type')
        if mtype == 'agent' and managed.get('agent_id') and managed.get('deployment_id'):
            return f"agent::{managed['agent_id']}::{managed['deployment_id']}"
        if mtype == 'adopted' and managed.get('agent_id') and managed.get('source_key'):
            return f"adopted::{managed['agent_id']}::{managed['source_key']}"
    return f"manual::{str(proxy.get('name') or '').strip()}"


def select_and_personalize_user_proxies(
    custom_proxies: Sequence[Dict[str, Any]],
    allowed_nodes: Sequence[str],
    user_creds_map: Optional[Dict[str, Dict[str, str]]] = None,
    relays: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    prefer_relay: bool = False,
) -> List[Dict[str, Any]]:
    """Filter authorized managed/adopted/manual nodes, inject per-user credentials, and rewrite relays."""
    allowed_set = {str(k).strip() for k in (allowed_nodes or ()) if str(k).strip()}
    if not allowed_set:
        return []
    creds_map = user_creds_map or {}
    selected: List[Dict[str, Any]] = []
    for raw in custom_proxies or ():
        if not isinstance(raw, dict):
            continue
        key = proxy_node_key(raw)
        if key not in allowed_set:
            continue
        node = copy.deepcopy(raw)
        managed = node.get('_managed_by')
        if isinstance(managed, dict) and managed.get('type') == 'agent' and key in creds_map:
            creds = creds_map[key]
            ptype = str(node.get('type') or '').lower()
            if ptype == 'vless' and creds.get('uuid'):
                node['uuid'] = creds['uuid']
            elif ptype in ('trojan', 'anytls', 'hysteria2') and creds.get('password'):
                node['password'] = creds['password']
        selected.append(node)

    if not selected:
        return []

    active_relays = list(relays or [])
    if prefer_relay and active_relays:
        effective, _ = apply_prefer_relay(selected, active_relays, prefer_relay=True)
    else:
        marked = [r for r in active_relays if isinstance(r, dict) and r.get('rewrite_subscription')]
        effective, _ = apply_prefer_relay(selected, marked, prefer_relay=bool(marked))

    decorated, _ = decorate_proxy_names(effective)
    return decorated


def build_minimal_mihomo_config(
    proxies: Sequence[Dict[str, Any]],
    *,
    info_notices: Sequence[str] = (),
    disabled_notice: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a standalone anti-leak minimal Mihomo config (2 proxy groups, CN/LAN split)."""
    base: Dict[str, Any] = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'ipv6': True,
        'unified-delay': True,
        'tcp-concurrent': True,
        'sniffer': copy.deepcopy(MINIMAL_SNIFFER),
        'dns': copy.deepcopy(MINIMAL_ANTI_LEAK_DNS),
    }

    if disabled_notice:
        label = str(disabled_notice)
        config = {
            **base,
            'proxies': [make_notice_proxy(label)],
            'proxy-groups': [
                {'name': '节点选择', 'type': 'select', 'proxies': [label]},
            ],
            'rules': ['MATCH,节点选择'],
        }
        assert_valid_mihomo_config(config)
        return config

    real_proxies = [copy.deepcopy(p) for p in (proxies or ()) if isinstance(p, dict) and p.get('name')]
    if not real_proxies:
        empty_label = '⚠️ 暂无可用节点'
        notice_proxies = [make_notice_proxy(n) for n in (info_notices or ())]
        notice_names = [p['name'] for p in notice_proxies]
        all_proxies = [*notice_proxies, make_notice_proxy(empty_label)]
        config = {
            **base,
            'proxies': all_proxies,
            'proxy-groups': [
                {'name': '节点选择', 'type': 'select', 'proxies': [*notice_names, empty_label]},
            ],
            'rules': ['MATCH,节点选择'],
        }
        assert_valid_mihomo_config(config)
        return config

    real_names = [str(p['name']) for p in real_proxies]
    seen_names = set(real_names)
    notice_proxies: List[Dict[str, Any]] = []
    notice_names: List[str] = []
    for raw_label in info_notices or ():
        label = str(raw_label or '').strip()
        if not label or label in seen_names:
            continue
        seen_names.add(label)
        notice_proxies.append(make_notice_proxy(label))
        notice_names.append(label)

    config = {
        **base,
        'proxies': [*notice_proxies, *real_proxies],
        'proxy-groups': [
            {
                'name': '节点选择',
                'type': 'select',
                'proxies': [*notice_names, '自动选择', *real_names],
            },
            {
                'name': '自动选择',
                'type': 'url-test',
                'url': 'https://www.gstatic.com/generate_204',
                'interval': 300,
                'tolerance': 50,
                'proxies': list(real_names),
            },
        ],
        'rules': list(MINIMAL_SPLIT_RULES),
    }
    assert_valid_mihomo_config(config)
    return config
