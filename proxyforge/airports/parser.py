"""机场 YAML / Base64 订阅解析，保持既有解析顺序。"""
import base64
import yaml

from proxyforge.subscription.links import parse_share_link


def parse_airport_response(text: str) -> list:
    # Try YAML first
    try:
        config = yaml.safe_load(text)
        if isinstance(config, dict) and "proxies" in config and isinstance(config["proxies"], list):
            return config["proxies"]
    except: pass

    # Try Base64
    try:
        t = text.strip()
        t += "=" * ((4 - len(t) % 4) % 4)
        decoded = base64.b64decode(t).decode('utf-8')
        proxies = []
        for line in decoded.splitlines():
            p = parse_share_link(line)
            if p: proxies.append(p)
        return proxies
    except: pass

    return []
