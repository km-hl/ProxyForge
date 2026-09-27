"""Pure source naming and node projection helpers."""
from typing import Any, Dict, List
import urllib.parse

CUSTOM_NODES_SOURCE = "_custom_nodes_"


def strip_internal_proxy_fields(node: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in node.items()
        if not str(key).startswith("_")
    }


def has_country_flag(name: str) -> bool:
    chars = list(str(name))
    for index in range(len(chars) - 1):
        first_code = ord(chars[index])
        second_code = ord(chars[index + 1])
        if 0x1F1E6 <= first_code <= 0x1F1FF and 0x1F1E6 <= second_code <= 0x1F1FF:
            return True
    return False


def keyword_matches_name(name: str, keyword: str) -> bool:
    import re
    if any(ord(char) > 127 for char in keyword):
        return keyword in name
    return re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", name) is not None


def add_flag_to_proxy_name(name: str) -> str:
    if not name or has_country_flag(name):
        return name

    lower_name = str(name).lower()
    flag_keywords = [
        ("\U0001F1ED\U0001F1F0", ["hk", "hkg", "hong kong", "香港", "港"]),
        ("\U0001F1EF\U0001F1F5", ["jp", "jpn", "japan", "tokyo", "osaka", "日本", "东京", "大阪"]),
        ("\U0001F1FA\U0001F1F8", ["us", "usa", "united states", "america", "los angeles", "美国", "美國", "洛杉矶", "洛杉磯", "圣何塞", "聖何塞"]),
        ("\U0001F1F8\U0001F1EC", ["sg", "singapore", "新加坡", "狮城", "獅城"]),
        ("\U0001F1F9\U0001F1FC", ["tw", "taiwan", "taipei", "台湾", "台灣", "台北"]),
        ("\U0001F1EC\U0001F1E7", ["uk", "gb", "united kingdom", "britain", "london", "英国", "英國", "伦敦", "倫敦"]),
        ("\U0001F1F0\U0001F1F7", ["kr", "korea", "seoul", "韩国", "韓國", "首尔", "首爾"]),
        ("\U0001F1E9\U0001F1EA", ["de", "germany", "frankfurt", "德国", "德國"]),
        ("\U0001F1EB\U0001F1F7", ["fr", "france", "法国", "法國"]),
        ("\U0001F1F7\U0001F1FA", ["ru", "russia", "俄罗斯", "俄羅斯"]),
        ("\U0001F1EE\U0001F1F3", ["in", "india", "印度"]),
    ]

    for flag, keywords in flag_keywords:
        if any(keyword_matches_name(lower_name, keyword) for keyword in keywords):
            return f"{flag} {name}"
    return name


def get_airport_name(item: Any, index: int = 0) -> str:
    if isinstance(item, dict):
        configured_name = str(item.get("name", "")).strip()
        url = str(item.get("url", "")).strip()
    else:
        configured_name = ""
        url = str(item).strip()
    hostname = urllib.parse.urlparse(url).hostname or ""
    return configured_name or hostname or f"Airport-{index + 1}"


def decorate_proxy_names(proxies: List[Dict[str, Any]]):
    output = []
    name_map = {}
    used_names = set()
    for proxy in proxies:
        if not isinstance(proxy, dict) or not proxy.get("name"):
            continue
        original_name = proxy["name"]
        output_name_base = add_flag_to_proxy_name(original_name)
        output_name = output_name_base
        suffix = 2
        while output_name in used_names:
            output_name = f"{output_name_base} ({suffix})"
            suffix += 1
        used_names.add(output_name)
        name_map[original_name] = output_name
        cleaned_proxy = strip_internal_proxy_fields(proxy)
        cleaned_proxy["name"] = output_name
        output.append(cleaned_proxy)
    return output, name_map
