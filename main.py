import os
import yaml
import logging
import base64
import json
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Query, Header, Depends, Body
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

TEMPLATE_PATH = "template.yaml"
CUSTOM_NODES_PATH = "custom_nodes.yaml"
DATA_DIR = "data"
CACHE_FILE_PATH = os.path.join(DATA_DIR, "airport_cache.yaml")
AIRPORTS_PATH = os.path.join(DATA_DIR, "airports.yaml")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True) 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    if not os.path.exists(CUSTOM_NODES_PATH):
        return []
    try:
        with open(CUSTOM_NODES_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            return nodes if isinstance(nodes, list) else []
    except Exception as e:
        logger.error(f"读取自建节点文件失败: {e}")
    return []

def save_custom_nodes(nodes: List[Dict[str, Any]]):
    with open(CUSTOM_NODES_PATH, "w", encoding="utf-8") as f:
        yaml.dump(nodes, f, allow_unicode=True, sort_keys=False)

def load_template_content() -> str:
    if not os.path.exists(TEMPLATE_PATH):
        return ""
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return f.read()

def save_template_content(content: str):
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

def fetch_airport_proxies() -> List[Dict[str, Any]]:
    urls_data = load_airports()
    if not urls_data:
        logger.warning("未配置机场订阅链接，跳过拉取。")
        return []
        
    headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
    all_proxies = []
    
    for item in urls_data:
        url = item.get("url", "") if isinstance(item, dict) else item
        if not isinstance(url, str) or not url.strip(): continue
        
        logger.info(f"正在从机场拉取节点: {url.strip()}")
        try:
            response = requests.get(url.strip(), headers=headers, timeout=10)
            response.raise_for_status()
            
            proxies = parse_airport_response(response.text)
            if proxies:
                logger.info(f"成功从 {url.strip()} 拉取到 {len(proxies)} 个节点")
                
                # Prepend airport name tag
                airport_name = item.get("name", "") if isinstance(item, dict) else ""
                if not airport_name:
                    airport_name = urllib.parse.urlparse(url.strip()).netloc
                
                for p in proxies:
                    if airport_name not in p.get("name", ""):
                        p["name"] = f"[{airport_name}] {p.get('name', 'node')}"
                        
                all_proxies.extend(proxies)
            else:
                logger.warning(f"机场订阅内容解析成功，但未找到代理节点: {url.strip()}")
        except Exception as e:
            logger.error(f"拉取机场订阅失败 {url.strip()}: {e}")
            
    return all_proxies

def fetch_single_airport_info(item) -> dict:
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
    
    try:
        headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
        res = requests.get(url, headers=headers, timeout=10)
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
    return info

def parse_share_link(link: str) -> dict:
    link = link.strip()
    if link.startswith("vmess://"):
        try:
            b64 = link[8:]
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.urlsafe_b64decode(b64).decode('utf-8'))
            return {
                "name": data.get("ps", "vmess_node"),
                "type": "vmess",
                "server": data.get("add", ""),
                "port": int(data.get("port", 443)),
                "uuid": data.get("id", ""),
                "alterId": int(data.get("aid", 0)),
                "cipher": data.get("scy", "auto"),
                "network": data.get("net", "tcp"),
                "ws-opts": {"path": data.get("path", ""), "headers": {"Host": data.get("host", "")}} if data.get("net") == "ws" else None,
                "tls": data.get("tls") == "tls",
                "sni": data.get("sni", "")
            }
        except: return None
    elif any(link.startswith(prefix) for prefix in ["vless://", "trojan://", "hysteria2://", "hy2://"]):
        try:
            parsed = urllib.parse.urlparse(link)
            scheme = "hysteria2" if parsed.scheme == "hy2" else parsed.scheme
            node = {
                "type": scheme,
                "server": parsed.hostname,
                "port": parsed.port,
                "name": urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{scheme}_node"
            }
            if scheme == "vless": node["uuid"] = parsed.username
            elif scheme == "trojan" or scheme == "hysteria2": node["password"] = parsed.username
                
            qs = urllib.parse.parse_qs(parsed.query)
            if "sni" in qs: node["sni"] = qs["sni"][0]
            if "peer" in qs: node["sni"] = qs["peer"][0]
            if "type" in qs: node["network"] = qs["type"][0]
            
            if scheme == "vless":
                sec = qs.get("security", [""])[0]
                node["tls"] = sec != "none"
                if sec == "reality":
                    node["tls"] = True
                    node["reality-opts"] = {"public-key": qs.get("pbk", [""])[0]}
                    if "fp" in qs: node["client-fingerprint"] = qs["fp"][0]
                    if "sid" in qs: node["reality-opts"]["short-id"] = qs["sid"][0]
                if node.get("network") == "ws":
                    node["ws-opts"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [""])[0]}}
            elif scheme == "hysteria2":
                if "obfs" in qs: node["obfs"] = qs["obfs"][0]
                if "obfs-password" in qs: node["obfs-password"] = qs["obfs-password"][0]
            return node
        except: return None
    return None

@cached(cache=subscription_cache)
def get_airport_proxies_cached() -> List[Dict[str, Any]]:
    return fetch_airport_proxies()

# ================= 订阅下发接口 (对外公开) =================

@app.get("/sub", response_class=PlainTextResponse)
def get_subscription(token: str = Query(..., description="安全验证 Token")):
    if token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        airport_proxies = get_airport_proxies_cached()
        if airport_proxies:
            save_cache_to_file(airport_proxies)
    except Exception as e:
        logger.error(f"尝试使用本地持久化备份，原因: {e}")
        airport_proxies = load_cache_from_file()

    custom_proxies = load_custom_nodes()
    all_proxies = airport_proxies + custom_proxies
    
    # 节点去重，防止多个机场出现同名节点或手动重复添加（保留第一个）
    seen_names = set()
    unique_proxies = []
    for p in all_proxies:
        if p["name"] not in seen_names:
            seen_names.add(p["name"])
            unique_proxies.append(p)
            
    proxy_names = [p["name"] for p in unique_proxies]

    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(status_code=500, detail="Template file not found")

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template_config = yaml.safe_load(f) or {}

    template_config["proxies"] = unique_proxies

    if "proxy-groups" in template_config and isinstance(template_config["proxy-groups"], list):
        for group in template_config["proxy-groups"]:
            existing_proxies = group.get("proxies", [])
            if existing_proxies is None:
                existing_proxies = []
                
            if "filter" in group:
                import re
                filter_regex = group["filter"]
                for name in proxy_names:
                    try:
                        if re.search(filter_regex, name) and name not in existing_proxies:
                            existing_proxies.append(name)
                    except: pass
                    
            if "use" in group and isinstance(group["use"], list):
                # Convert 'use' to airport tags filtering
                for name in proxy_names:
                    for u in group["use"]:
                        # if the node name contains [AirportName]
                        if f"[{u}]" in name and name not in existing_proxies:
                            existing_proxies.append(name)
                            break
                            
            if not existing_proxies and group.get("type") != "select":
                if group.get("include-all", False) or ("filter" not in group and "use" not in group):
                    for name in proxy_names:
                        if name not in existing_proxies:
                            existing_proxies.append(name)
                        
            group["proxies"] = existing_proxies
            
            # Remove proxyforge-specific or mihomo-incompatible fields from the final output
            for field in ["include-all", "filter", "use"]:
                if field in group:
                    del group[field]

    return yaml.dump(template_config, allow_unicode=True, sort_keys=False)

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
def get_airports_info():
    urls_data = load_airports()
    results = []
    if urls_data:
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(fetch_single_airport_info, urls_data))
    return {"info": results}

class ParseLinksModel(BaseModel):
    links: List[str]

@app.post("/api/parse-links", dependencies=[Depends(verify_api_token)])
def parse_links_api(data: ParseLinksModel):
    nodes = []
    for link in data.links:
        parsed = parse_share_link(link)
        if parsed:
            parsed = {k: v for k, v in parsed.items() if v is not None}
            nodes.append(parsed)
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
        yaml.safe_load(data.content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YAML 格式错误: {e}")
    save_template_content(data.content)
    return {"status": "ok"}

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
