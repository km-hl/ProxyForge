import os
import copy
import shutil
import yaml
import logging
import base64
import json
import urllib.parse
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Query, Header, Depends, Body, Request
from fastapi.responses import PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from cachetools import cached, TTLCache
from typing import List, Dict, Any
from dotenv import load_dotenv
from pydantic import BaseModel

# ================= 加载环境变量 =================
load_dotenv()
ENV_FILE = ".env"

def get_env_var(key, default=""):
    return os.environ.get(key) or os.getenv(key, default)

SECRET_TOKEN = get_env_var("SECRET_TOKEN", "my_secret_token")

DATA_DIR = "data"
TEMPLATE_PATH = os.path.join(DATA_DIR, "template.yaml")
TEMPLATE_EXAMPLE_PATH = "template.example.yaml"
LEGACY_TEMPLATE_PATH = "template.yaml"
CUSTOM_NODES_PATH = os.path.join(DATA_DIR, "custom_nodes.yaml")
LEGACY_CUSTOM_NODES_PATH = "custom_nodes.yaml"
CACHE_FILE_PATH = os.path.join(DATA_DIR, "airport_cache.yaml")
AIRPORTS_PATH = os.path.join(DATA_DIR, "airports.yaml")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True) 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def initialize_template_storage() -> str:
    """Create the persistent runtime template, migrating legacy installs first."""
    if os.path.isfile(TEMPLATE_PATH):
        return TEMPLATE_PATH
    if os.path.isdir(TEMPLATE_PATH):
        logger.error(f"模板路径是目录而不是文件: {TEMPLATE_PATH}")
        return ""

    for source, description in [
        (LEGACY_TEMPLATE_PATH, "旧版运行配置"),
        (TEMPLATE_EXAMPLE_PATH, "默认模板"),
    ]:
        if not os.path.isfile(source):
            continue
        try:
            shutil.copyfile(source, TEMPLATE_PATH)
            logger.info(f"已从{description}初始化持久化模板: {TEMPLATE_PATH}")
            return TEMPLATE_PATH
        except OSError as e:
            logger.error(f"初始化持久化模板失败: {e}")
            return ""
    logger.error(
        f"找不到模板来源，需要 {TEMPLATE_PATH}、{LEGACY_TEMPLATE_PATH} "
        f"或 {TEMPLATE_EXAMPLE_PATH} 中的任意一个文件"
    )
    return ""

initialize_template_storage()

def initialize_custom_nodes_storage() -> str:
    """Migrate the legacy custom node file into the persistent data directory."""
    if os.path.isfile(CUSTOM_NODES_PATH):
        return CUSTOM_NODES_PATH
    if os.path.isdir(CUSTOM_NODES_PATH):
        logger.error(f"自建节点路径是目录而不是文件: {CUSTOM_NODES_PATH}")
        return ""
    if not os.path.isfile(LEGACY_CUSTOM_NODES_PATH):
        return ""
    try:
        shutil.copyfile(LEGACY_CUSTOM_NODES_PATH, CUSTOM_NODES_PATH)
        logger.info(f"已迁移旧版自建节点文件: {CUSTOM_NODES_PATH}")
        return CUSTOM_NODES_PATH
    except OSError as e:
        logger.error(f"迁移自建节点文件失败: {e}")
        return ""

initialize_custom_nodes_storage()

app = FastAPI(title="ProxyForge", description="专属节点订阅聚合与配置下发中心")

subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60)

# ================= 核心读写逻辑 =================

def load_airports() -> List[str]:
    # 兼容性迁移逻辑：如果还没创建 airports.yaml，但 .env 里有旧的 AIRPORT_SUB_URL
    if not os.path.exists(AIRPORTS_PATH):
        legacy_url = get_env_var("AIRPORT_SUB_URL", "")
        if legacy_url:
            save_airports([legacy_url])
            return [legacy_url]
        return []
        
    try:
        with open(AIRPORTS_PATH, "r", encoding="utf-8") as f:
            urls = yaml.safe_load(f)
            return urls if isinstance(urls, list) else []
    except Exception as e:
        logger.error(f"读取机场列表失败: {e}")
    return []

def save_airports(urls: List[str]):
    with open(AIRPORTS_PATH, "w", encoding="utf-8") as f:
        yaml.dump(urls, f, allow_unicode=True, sort_keys=False)

def load_custom_nodes() -> List[Dict[str, Any]]:
    initialize_custom_nodes_storage()
    if not os.path.exists(CUSTOM_NODES_PATH):
        return []
    try:
        with open(CUSTOM_NODES_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        node["_airport_name"] = "_custom_nodes_"
                return nodes
            return []
    except Exception as e:
        logger.error(f"读取自建节点文件失败: {e}")
    return []

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

def save_custom_nodes(nodes: List[Dict[str, Any]]):
    cleaned_nodes = [
        strip_internal_proxy_fields(node)
        for node in nodes
        if isinstance(node, dict)
    ]
    os.makedirs(os.path.dirname(CUSTOM_NODES_PATH), exist_ok=True)
    with open(CUSTOM_NODES_PATH, "w", encoding="utf-8") as f:
        yaml.dump(cleaned_nodes, f, allow_unicode=True, sort_keys=False)

def load_template_content() -> str:
    if not initialize_template_storage():
        return ""
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return f.read()

def save_template_content(content: str):
    os.makedirs(os.path.dirname(TEMPLATE_PATH), exist_ok=True)
    with open(TEMPLATE_PATH, "w", encoding="utf-8") as f:
        f.write(content)

def save_cache_to_file(proxies: List[Dict[str, Any]]):
    try:
        with open(CACHE_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.dump(proxies, f, allow_unicode=True, sort_keys=False)
    except Exception as e:
        logger.error(f"持久化节点缓存失败: {e}")

def load_cache_from_file() -> List[Dict[str, Any]]:
    if not os.path.exists(CACHE_FILE_PATH):
        return []
    try:
        with open(CACHE_FILE_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            return nodes if isinstance(nodes, list) else []
    except Exception as e:
        logger.error(f"读取节点持久化缓存失败: {e}")
    return []

def parse_airport_response(text: str) -> list:
    # Try YAML first
    try:
        config = yaml.safe_load(text)
        if isinstance(config, dict) and "proxies" in config and isinstance(config["proxies"], list):
            return config["proxies"]
    except: pass
        
    # Try Base64
    try:
        import base64
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

def merge_airport_proxies_with_cache(
    proxies: List[Dict[str, Any]], airports: List[Any]
):
    merged = list(proxies or [])
    cached = load_cache_from_file()
    available_sources = {
        str(proxy.get("_airport_name", "")).lower()
        for proxy in merged if isinstance(proxy, dict)
    }
    missing_sources = []
    for index, airport in enumerate(airports):
        source_name = get_airport_name(airport, index)
        source_key = source_name.lower()
        if source_key not in available_sources:
            cached_for_source = [
                proxy for proxy in cached
                if isinstance(proxy, dict) and str(proxy.get("_airport_name", "")).lower() == source_key
            ]
            if cached_for_source:
                merged.extend(cached_for_source)
                available_sources.add(source_key)
        if source_key not in available_sources:
            missing_sources.append(source_name)
    return merged, missing_sources

def get_airport_name(item: Any, index: int = 0) -> str:
    if isinstance(item, dict):
        configured_name = str(item.get("name", "")).strip()
        url = str(item.get("url", "")).strip()
    else:
        configured_name = ""
        url = str(item).strip()
    return configured_name or urllib.parse.urlparse(url).netloc or f"Airport-{index + 1}"

def fetch_airport_item(item: Any, index: int = 0) -> List[Dict[str, Any]]:
    url = item.get("url", "") if isinstance(item, dict) else item
    if not isinstance(url, str) or not url.strip():
        return []

    headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
    logger.info(f"正在从机场拉取节点: {url.strip()}")
    try:
        response = requests.get(url.strip(), headers=headers, timeout=30)
        response.raise_for_status()
        proxies = parse_airport_response(response.text)
        if proxies:
            airport_name = get_airport_name(item, index)
            for proxy in proxies:
                if isinstance(proxy, dict):
                    proxy["_airport_name"] = airport_name
            logger.info(f"成功从 {airport_name} 拉取到 {len(proxies)} 个节点")
            return proxies
        logger.warning(f"机场订阅内容解析成功，但未找到代理节点: {url.strip()}")
    except Exception as e:
        logger.error(f"拉取机场订阅失败 {url.strip()}: {e}")
    return []

def fetch_airport_proxies() -> List[Dict[str, Any]]:
    urls_data = load_airports()
    if not urls_data:
        logger.warning("未配置机场订阅链接，跳过拉取。")
        return []
        
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda pair: fetch_airport_item(pair[1], pair[0]), enumerate(urls_data)))
        
    all_proxies = []
    seen_names = set()
    
    for proxies in results:
        for p in proxies:
            original_name = p.get('name', 'node')
            name = original_name
            airport_name = p.get("_airport_name", "")
            collision_count = 1
            while name in seen_names:
                name = f"{original_name} ({airport_name})"
                if name in seen_names:
                    name = f"{original_name} ({airport_name} {collision_count})"
                    collision_count += 1
            seen_names.add(name)
            p["name"] = name
            all_proxies.append(p)
            
    return all_proxies

def fetch_single_airport_info(item, force=False) -> dict:
    url = item.get("url", "").strip() if isinstance(item, dict) else item.strip()
    custom_name = item.get("name", "") if isinstance(item, dict) else ""
    
    info = {
        "url": url,
        "name": custom_name or urllib.parse.urlparse(url).netloc,
        "nodesCount": 0,
        "upload": 0,
        "download": 0,
        "total": 0,
        "expire": 0,
        "error": None
    }
    if not url: return info
    
    import os
    cache_file = os.path.join(DATA_DIR, "airports_info_cache.json")
    cache_data = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)
        except: pass
        
    if not force and url in cache_data:
        cached_info = cache_data[url]
        # Check if cache is less than 24 hours old
        import time
        if time.time() - cached_info.get("_timestamp", 0) < 24 * 3600:
            ret_info = cached_info["info"]
            ret_info["_timestamp"] = cached_info.get("_timestamp", 0)
            return ret_info
            
    try:
        headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
        res = requests.get(url, headers=headers, timeout=30)
        res.raise_for_status()
        
        # 尝试提取名称
        if not custom_name:
            cd = res.headers.get("content-disposition", "")
            if "filename=" in cd:
                import re
                m = re.search(r'filename=["\']?([^"\';]+)', cd)
                if m:
                    info["name"] = urllib.parse.unquote(m.group(1))
                
        # 尝试提取流量信息
        userinfo = res.headers.get("subscription-userinfo", "")
        if userinfo:
            import re
            for k in ["upload", "download", "total", "expire"]:
                m = re.search(rf'{k}\s*=\s*(\d+)', userinfo)
                if m:
                    info[k] = int(m.group(1))
                    
        proxies = parse_airport_response(res.text)
        info["nodesCount"] = len(proxies)
            
    except Exception as e:
        info["error"] = str(e)
        
    import time
    timestamp = time.time()
    info["_timestamp"] = timestamp
    cache_data[url] = {"info": info, "_timestamp": timestamp}
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f)
    except: pass
        
    return info

def parse_share_link(link: str) -> dict:
    link = link.strip()

    def b64_decode(value: str) -> str:
        value = value.strip()
        value += "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(value).decode("utf-8")

    def first(qs: dict, *keys: str, default: str = "") -> str:
        for key in keys:
            if key in qs and qs[key]:
                return qs[key][0]
        return default

    def as_bool(value: str) -> bool:
        return str(value).lower() in {"1", "true", "yes"}

    def split_list(value: str) -> list:
        return [item for item in value.replace(",", "\n").splitlines() if item]

    def add_common_tls_fields(node: dict, qs: dict, sni_field: str):
        sni = first(qs, "sni", "peer")
        if sni:
            node[sni_field] = sni
        alpn = first(qs, "alpn")
        if alpn:
            node["alpn"] = split_list(alpn)
        fingerprint = first(qs, "fingerprint")
        if fingerprint:
            node["fingerprint"] = fingerprint
        client_fingerprint = first(qs, "fp", "client-fingerprint")
        if client_fingerprint:
            node["client-fingerprint"] = client_fingerprint
        skip_cert_verify = first(qs, "skip-cert-verify", "allowInsecure", "insecure")
        if skip_cert_verify:
            node["skip-cert-verify"] = as_bool(skip_cert_verify)

    def add_transport_opts(node: dict, qs: dict):
        network = node.get("network")
        path = first(qs, "path", default="/")
        host = first(qs, "host")
        if network == "ws":
            ws_opts = {"path": path}
            if host:
                ws_opts["headers"] = {"Host": host}
            node["ws-opts"] = ws_opts
        elif network == "grpc":
            service_name = first(qs, "serviceName", "service-name", "grpc-service-name")
            if service_name:
                node["grpc-opts"] = {"grpc-service-name": service_name}
        elif network == "h2":
            h2_opts = {"path": path}
            if host:
                h2_opts["host"] = split_list(host)
            node["h2-opts"] = h2_opts
        elif network == "xhttp":
            xhttp_opts = {"path": path}
            if host:
                xhttp_opts["host"] = host
            mode = first(qs, "mode")
            if mode:
                xhttp_opts["mode"] = mode
            node["xhttp-opts"] = xhttp_opts

    if link.lower().startswith("vmess://"):
        try:
            b64 = link[8:]
            data = json.loads(b64_decode(b64))
            node = {
                "name": data.get("ps", "vmess_node"),
                "type": "vmess",
                "server": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id", ""),
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "tls": data.get("tls") == "tls",
                "udp": True
            }
            if data.get("net") == "ws":
                node["ws-opts"] = {"path": data.get("path", ""), "headers": {"Host": data.get("host", "")}}
            if data.get("sni"):
                node["servername"] = data.get("sni")
            return node
        except: return None
    elif link.lower().startswith("ss://"):
        try:
            parsed = urllib.parse.urlparse(link)
            userinfo = parsed.username or ""
            server = parsed.hostname
            port = parsed.port
            cipher = ""
            password = ""

            if parsed.password is not None:
                cipher = urllib.parse.unquote(parsed.username or "")
                password = urllib.parse.unquote(parsed.password)
            elif parsed.hostname and parsed.port and userinfo:
                decoded_userinfo = b64_decode(userinfo)
                cipher, password = decoded_userinfo.split(":", 1)
            else:
                raw = parsed.netloc or link[5:].split("#", 1)[0].split("?", 1)[0]
                decoded = b64_decode(raw)
                userinfo, address = decoded.rsplit("@", 1)
                cipher, password = userinfo.split(":", 1)
                server, port_text = address.rsplit(":", 1)
                port = int(port_text)

            return {
                "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else "ss_node",
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": cipher,
                "password": password,
                "udp": True
            }
        except: return None
    elif any(link.lower().startswith(prefix) for prefix in ["vless://", "trojan://", "hysteria2://", "hy2://"]):
        try:
            parsed = urllib.parse.urlparse(link)
            scheme = "hysteria2" if parsed.scheme == "hy2" else parsed.scheme

            # Hysteria 2 permits both userpass authentication ("user:pass") and
            # multi-port authorities such as host:443,2000-3000. urllib's
            # parsed.username/parsed.port either truncates or rejects those valid
            # forms, so preserve the raw authority for Hysteria 2.
            raw_authority = parsed.netloc.rsplit("@", 1)
            raw_auth = urllib.parse.unquote(raw_authority[0]) if len(raw_authority) == 2 else ""
            raw_host_port = raw_authority[-1]
            port_value = None
            ports_value = ""
            if scheme == "hysteria2":
                if raw_host_port.startswith("["):
                    closing_bracket = raw_host_port.find("]")
                    port_spec = raw_host_port[closing_bracket + 2:] if closing_bracket >= 0 and raw_host_port[closing_bracket + 1:closing_bracket + 2] == ":" else ""
                else:
                    host_parts = raw_host_port.rsplit(":", 1)
                    port_spec = host_parts[1] if len(host_parts) == 2 else ""

                port_spec = urllib.parse.unquote(port_spec)
                if port_spec and re.fullmatch(r"[0-9,-]+", port_spec):
                    if "," in port_spec or "-" in port_spec:
                        ports_value = port_spec
                        first_port = re.search(r"\d+", port_spec)
                        port_value = int(first_port.group(0)) if first_port else 443
                    else:
                        port_value = int(port_spec)
                else:
                    # The Hysteria URI specification defines 443 as the default.
                    port_value = 443
            else:
                port_value = parsed.port

            node = {
                "type": scheme,
                "server": parsed.hostname,
                "port": port_value,
                "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{scheme}_node",
                "udp": True
            }
            if scheme == "vless": node["uuid"] = urllib.parse.unquote(parsed.username or "")
            elif scheme == "trojan": node["password"] = urllib.parse.unquote(parsed.username or "")
            elif scheme == "hysteria2":
                node["password"] = raw_auth
                if ports_value:
                    node["ports"] = ports_value
                
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if "type" in qs: node["network"] = qs["type"][0]
            
            if scheme == "vless":
                add_common_tls_fields(node, qs, "servername")
                sec = first(qs, "security").lower()
                node["tls"] = sec != "none"
                encryption = first(qs, "encryption")
                if encryption:
                    node["encryption"] = encryption
                flow = first(qs, "flow")
                if flow:
                    node["flow"] = flow
                packet_encoding = first(qs, "packetEncoding", "packet-encoding")
                if packet_encoding:
                    node["packet-encoding"] = packet_encoding
                if sec == "reality":
                    node["tls"] = True
                    node["reality-opts"] = {"public-key": first(qs, "pbk")}
                    if "sid" in qs: node["reality-opts"]["short-id"] = qs["sid"][0]
                    if "spx" in qs: node["reality-opts"]["spider-x"] = qs["spx"][0]
                add_transport_opts(node, qs)
            elif scheme == "trojan":
                add_common_tls_fields(node, qs, "sni")
                add_transport_opts(node, qs)
            elif scheme == "hysteria2":
                add_common_tls_fields(node, qs, "sni")
                auth = first(qs, "auth")
                if auth and not node["password"]:
                    node["password"] = auth
                obfs = first(qs, "obfs")
                if obfs and obfs.lower() != "none":
                    node["obfs"] = obfs
                obfs_password = first(qs, "obfs-password", "obfsPassword")
                if obfs_password and node.get("obfs"):
                    node["obfs-password"] = obfs_password
                pin_sha256 = first(qs, "pinSHA256", "pin-sha256")
                if pin_sha256:
                    node["fingerprint"] = pin_sha256
                field_aliases = {
                    "ports": ("ports", "mport"),
                    "hop-interval": ("hop-interval", "hopInterval"),
                    "up": ("up", "upmbps"),
                    "down": ("down", "downmbps"),
                    "obfs-min-packet-size": ("obfs-min-packet-size",),
                    "obfs-max-packet-size": ("obfs-max-packet-size",),
                }
                for field, aliases in field_aliases.items():
                    value = first(qs, *aliases)
                    if value:
                        node[field] = value
            return node
        except: return None
    return None

class ConfigValidationError(ValueError):
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__("\n".join(errors))

def _is_valid_port(value: Any) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except (TypeError, ValueError):
        return False

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
            if not proxy.get("server"):
                errors.append(f"{prefix} ({name or '未命名'}) 缺少 server")
            if proxy_type == "hysteria2":
                ports = proxy.get("ports")
                if ports and not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", str(ports)):
                    errors.append(f"{prefix} ({name or '未命名'}) 的 ports 格式无效: {ports}")
                if not ports and not _is_valid_port(proxy.get("port")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port/ports")
                if not str(proxy.get("password", "")):
                    errors.append(f"{prefix} ({name or '未命名'}) 缺少 Hysteria2 password")
                if proxy.get("obfs") not in {None, "", "salamander"}:
                    errors.append(f"{prefix} ({name or '未命名'}) 的 Mihomo Hysteria2 obfs 不受支持: {proxy.get('obfs')}")
                if proxy.get("obfs") and not proxy.get("obfs-password"):
                    errors.append(f"{prefix} ({name or '未命名'}) 启用了 obfs 但缺少 obfs-password")
            elif not _is_valid_port(proxy.get("port")):
                errors.append(f"{prefix} ({name or '未命名'}) 缺少有效的 port: {proxy.get('port')}")
    return errors

def validate_mihomo_config(
    config: Any,
    external_proxy_names: Any = None,
    external_provider_names: Any = None,
) -> List[str]:
    """Perform static YAML and Mihomo reference checks before publishing config."""
    if not isinstance(config, dict):
        return ["配置根节点必须是 YAML 对象"]

    errors = []
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

def build_subscription_config(
    template_config: Dict[str, Any],
    custom_proxies: List[Dict[str, Any]],
    airports: List[Any],
    base_url: str,
    token: str,
) -> Dict[str, Any]:
    config = copy.deepcopy(template_config)
    if not isinstance(config, dict):
        raise ConfigValidationError(["模板根节点必须是 YAML 对象"])

    output_proxies, proxy_name_map = decorate_proxy_names(custom_proxies)
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
                if str(source).lower() == "_custom_nodes_":
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

@cached(cache=subscription_cache)
def get_airport_proxies_cached() -> List[Dict[str, Any]]:
    return fetch_airport_proxies()

# ================= 订阅下发接口 (对外公开) =================

@app.get("/provider/{airport_index}", response_class=PlainTextResponse)
def get_airport_provider(
    airport_index: int,
    token: str = Query(..., description="安全验证 Token"),
):
    if token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    airports = load_airports()
    if airport_index < 0 or airport_index >= len(airports):
        raise HTTPException(status_code=404, detail="Airport provider not found")

    airport = airports[airport_index]
    proxies = fetch_airport_item(airport, airport_index)
    if not proxies:
        source_name = get_airport_name(airport, airport_index).lower()
        proxies = [
            proxy for proxy in load_cache_from_file()
            if isinstance(proxy, dict) and str(proxy.get("_airport_name", "")).lower() == source_name
        ]
    if not proxies:
        raise HTTPException(status_code=502, detail="机场订阅暂时不可用，且没有可用缓存")

    output_proxies, _ = decorate_proxy_names(proxies)
    errors = validate_proxy_nodes(output_proxies, location="payload")
    if errors:
        raise HTTPException(status_code=422, detail={"message": "机场节点校验失败", "errors": errors})
    return PlainTextResponse(
        content=yaml.safe_dump({"payload": output_proxies}, allow_unicode=True, sort_keys=False),
    )

@app.get("/sub", response_class=PlainTextResponse)
def get_subscription(
    request: Request,
    token: str = Query(..., description="安全验证 Token"),
    name: str = Query("ProxyForge", description="自定义订阅名称")
):
    if token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        try:
            airport_proxies = get_airport_proxies_cached()
        except Exception as e:
            logger.error(f"尝试使用本地持久化备份，原因: {e}")
            airport_proxies = load_cache_from_file()

        airports = load_airports()
        # Fill a temporarily unavailable airport from its last persisted payload,
        # then require every configured provider to have at least one checked node.
        airport_proxies, unavailable_sources = merge_airport_proxies_with_cache(
            airport_proxies, airports
        )
        if unavailable_sources:
            raise ConfigValidationError([
                f"机场 [{source}] 当前未拉取到节点，且没有可用缓存"
                for source in unavailable_sources
            ])
        if airport_proxies:
            save_cache_to_file(airport_proxies)

        custom_proxies = load_custom_nodes()

        template_content = load_template_content()
        if not template_content:
            raise HTTPException(status_code=500, detail="Template file not found")
        template_config = yaml.safe_load(template_content) or {}

        # Airport nodes remain independent proxy-providers. The already fetched
        # nodes above are still validated so a broken provider cannot be published
        # unnoticed merely because its payload is remote.
        airport_errors = []
        for index, airport_proxy in enumerate(airport_proxies, 1):
            # Names may legitimately repeat across different providers; the
            # provider override prefixes them at load time. Validate each node's
            # protocol fields here, while the provider endpoint validates its
            # decorated payload as a whole.
            airport_errors.extend(
                validate_proxy_nodes([airport_proxy], location=f"airport-proxies[{index}]")
            )
        if airport_errors:
            raise ConfigValidationError(airport_errors)
        final_config = build_subscription_config(
            template_config,
            custom_proxies,
            airports,
            str(request.base_url).rstrip("/"),
            token,
        )
        yaml_content = yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)
        
        encoded_name = urllib.parse.quote(name)
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
            "Profile-Title": encoded_name
        }
        
        return PlainTextResponse(content=yaml_content, headers=headers)
    except ConfigValidationError as e:
        logger.warning("订阅配置校验失败: %s", "; ".join(e.errors))
        return PlainTextResponse(
            content="订阅配置校验失败:\n- " + "\n- ".join(e.errors),
            status_code=422,
        )
    except HTTPException:
        raise
    except Exception:
        import traceback
        error_msg = traceback.format_exc()
        logger.error(f"Subscription Generation Error: {error_msg}")
        return PlainTextResponse(content="生成订阅时发生内部错误，请查看服务端日志。", status_code=500)

# ================= 后台管理 API 接口 (需鉴权) =================

def verify_api_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    token = authorization.replace("Bearer ", "").strip()
    if token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid Token")
    return True

@app.post("/api/auth")
def auth_login(token: str = Body(..., embed=True)):
    if token == SECRET_TOKEN:
        return {"status": "ok"}
    raise HTTPException(status_code=401, detail="Invalid Token")

@app.get("/api/config", dependencies=[Depends(verify_api_token)])
def get_config():
    return {
        "SECRET_TOKEN": SECRET_TOKEN
    }

class ConfigModel(BaseModel):
    SECRET_TOKEN: str

@app.post("/api/config", dependencies=[Depends(verify_api_token)])
def update_config(config: ConfigModel):
    global SECRET_TOKEN
    
    lines = []
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
    
    new_lines = []
    token_updated = False
    for line in lines:
        if line.startswith("SECRET_TOKEN="):
            new_lines.append(f'SECRET_TOKEN="{config.SECRET_TOKEN}"\n')
            token_updated = True
        elif line.startswith("AIRPORT_SUB_URL="):
            continue 
        else:
            new_lines.append(line)
            
    if not token_updated:
        new_lines.append(f'SECRET_TOKEN="{config.SECRET_TOKEN}"\n')

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    
    SECRET_TOKEN = config.SECRET_TOKEN
    os.environ["SECRET_TOKEN"] = SECRET_TOKEN
    
    return {"status": "ok"}

@app.get("/api/airports", dependencies=[Depends(verify_api_token)])
def get_airports():
    return {"urls": load_airports()}

class AirportsModel(BaseModel):
    urls: List[Any]

@app.post("/api/airports", dependencies=[Depends(verify_api_token)])
def update_airports(data: AirportsModel):
    save_airports(data.urls)
    subscription_cache.clear()
    return {"status": "ok"}

@app.get("/api/airports/info", dependencies=[Depends(verify_api_token)])
def get_airports_info(force_indices: str = ""):
    urls_data = load_airports()
    results = []
    
    force_idx_list = []
    if force_indices:
        try:
            force_idx_list = [int(x) for x in force_indices.split(",") if x.strip()]
        except: pass
        
    if urls_data:
        def fetch_wrapper(args):
            idx, item = args
            force = (idx in force_idx_list) or (force_indices == "all")
            return fetch_single_airport_info(item, force=force)
            
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(fetch_wrapper, enumerate(urls_data)))
    return {"info": results}

class ParseLinksModel(BaseModel):
    links: List[str]

@app.post("/api/parse-links", dependencies=[Depends(verify_api_token)])
def parse_links_api(data: ParseLinksModel):
    nodes = []
    errors = []
    for index, link in enumerate(data.links, 1):
        parsed = parse_share_link(link)
        if parsed:
            parsed = {k: v for k, v in parsed.items() if v is not None}
            node_errors = validate_proxy_nodes([parsed], location=f"links[{index}]")
            if node_errors:
                errors.extend(node_errors)
            else:
                nodes.append(parsed)
        else:
            scheme = link.split(":", 1)[0] if ":" in link else "未知协议"
            errors.append(f"links[{index}] ({scheme}) 分享链接格式无效")
    if errors:
        raise HTTPException(status_code=400, detail={"message": "分享链接校验失败", "errors": errors})
    return {"nodes": nodes}

@app.get("/api/nodes", dependencies=[Depends(verify_api_token)])
def get_nodes():
    return {"nodes": load_custom_nodes()}

@app.get("/api/proxies", dependencies=[Depends(verify_api_token)])
def get_all_proxies():
    custom = load_custom_nodes()
    airports = get_airport_proxies_cached()
    return {"proxies": custom + airports}

class NodesModel(BaseModel):
    nodes: List[Dict[str, Any]]

@app.post("/api/nodes", dependencies=[Depends(verify_api_token)])
def update_nodes(data: NodesModel):
    errors = validate_proxy_nodes(data.nodes, location="nodes")
    if errors:
        raise HTTPException(status_code=400, detail={"message": "节点配置校验失败", "errors": errors})
    save_custom_nodes(data.nodes)
    return {"status": "ok"}

@app.get("/api/template", dependencies=[Depends(verify_api_token)])
def get_template():
    return {"content": load_template_content()}

class TemplateModel(BaseModel):
    content: str

@app.post("/api/template", dependencies=[Depends(verify_api_token)])
def update_template(data: TemplateModel):
    try:
        config = yaml.safe_load(data.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YAML 格式错误: {e}")
    provider_names = [get_airport_name(item, index) for index, item in enumerate(load_airports())]
    custom_names = [
        proxy.get("name") for proxy in load_custom_nodes()
        if isinstance(proxy, dict) and proxy.get("name")
    ]
    errors = validate_mihomo_config(
        config,
        external_proxy_names=custom_names,
        external_provider_names=provider_names,
    )
    if errors:
        raise HTTPException(status_code=400, detail={"message": "Mihomo 配置校验失败", "errors": errors})
    save_template_content(data.content)
    return {"status": "ok"}

import asyncio
from cachetools.keys import hashkey

# ================= 后台定时刷新任务 =================

async def background_airport_updater():
    # 启动后先等待 5 分钟，错开刚启动时的并发请求
    await asyncio.sleep(300)
    while True:
        try:
            logger.info("后台定时任务触发：开始静默拉取机场节点...")
            # 利用已有的多线程逻辑并发拉取
            proxies = fetch_airport_proxies()
            proxies, missing_sources = merge_airport_proxies_with_cache(proxies, load_airports())
            if proxies and not missing_sources:
                save_cache_to_file(proxies)
                subscription_cache.clear()
                # 预热内存缓存，后续 /sub 请求将直接 0 延迟命中
                subscription_cache[hashkey()] = proxies
                logger.info(f"后台定时任务完成，成功更新了 {len(proxies)} 个机场节点")
            else:
                logger.warning(
                    "后台定时任务：机场数据不完整 (%s)，放弃覆盖旧缓存",
                    ", ".join(missing_sources) if missing_sources else "无节点",
                )
        except Exception as e:
            logger.error(f"后台定时任务异常: {e}")
            
        # 默认每隔 4 小时更新一次
        await asyncio.sleep(4 * 3600)

@app.on_event("startup")
async def startup_event():
    logger.info("系统启动：已注册后台定时更新任务")
    asyncio.create_task(background_airport_updater())

# ================= 前端静态页面挂载 =================

@app.get("/")
def serve_dashboard():
    index_path = "static/index.html"
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return PlainTextResponse("Static files not found.", status_code=404)

app.mount("/static", StaticFiles(directory="static"), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("WEB_PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
