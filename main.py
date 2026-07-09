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
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        node["_airport_name"] = "_custom_nodes_"
                return nodes
            return []
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
        
    def fetch_one(item):
        url = item.get("url", "") if isinstance(item, dict) else item
        if not isinstance(url, str) or not url.strip(): return []
        
        headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
        logger.info(f"正在从机场拉取节点: {url.strip()}")
        try:
            response = requests.get(url.strip(), headers=headers, timeout=30)
            response.raise_for_status()
            
            proxies = parse_airport_response(response.text)
            if proxies:
                logger.info(f"成功从 {url.strip()} 拉取到 {len(proxies)} 个节点")
                airport_name = item.get("name", "") if isinstance(item, dict) else ""
                if not airport_name:
                    airport_name = urllib.parse.urlparse(url.strip()).netloc
                for p in proxies:
                    p["_airport_name"] = airport_name
                return proxies
            else:
                logger.warning(f"机场订阅内容解析成功，但未找到代理节点: {url.strip()}")
        except Exception as e:
            logger.error(f"拉取机场订阅失败 {url.strip()}: {e}")
        return []

    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(fetch_one, urls_data))
        
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
            return cached_info["info"]
            
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
    cache_data[url] = {"info": info, "_timestamp": time.time()}
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(cache_data, f)
    except: pass
        
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
def get_subscription(
    token: str = Query(..., description="安全验证 Token"),
    name: str = Query("ProxyForge", description="自定义订阅名称")
):
    if token != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
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
            if isinstance(p, dict) and p.get("name"):
                if p["name"] not in seen_names:
                    seen_names.add(p["name"])
                    unique_proxies.append(p)
                
        proxy_names = [p["name"] for p in unique_proxies]

        if not os.path.exists(TEMPLATE_PATH):
            raise HTTPException(status_code=500, detail="Template file not found")

        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            template_config = yaml.safe_load(f) or {}

        template_config["proxies"] = unique_proxies
        all_proxy_names = {p["name"] for p in unique_proxies if p.get("name")}
        all_group_names = {g["name"] for g in template_config.get("proxy-groups", []) if g.get("name")}
        valid_manual_proxies = all_proxy_names.union(all_group_names).union({"DIRECT", "REJECT"})

        if "proxy-groups" in template_config and isinstance(template_config["proxy-groups"], list):
            for group in template_config["proxy-groups"]:
                existing_proxies = group.get("proxies", [])
                if not isinstance(existing_proxies, list):
                    existing_proxies = []
                    
                # 1. Collect candidates based on 'use'
                candidates = []
                if "use" in group and isinstance(group["use"], list):
                    for p in unique_proxies:
                        if p.get("_airport_name") in group["use"]:
                            candidates.append(p)
                elif "filter" in group or group.get("include-all", False):
                    candidates = unique_proxies
                    
                # 2. Filter candidates with regex if present
                matched_candidates = []
                if "filter" in group:
                    import re
                    filter_regex = group["filter"]
                    for p in candidates:
                        try:
                            if re.search(filter_regex, str(p.get("name", ""))):
                                matched_candidates.append(p)
                        except: pass
                else:
                    matched_candidates = candidates
                    
                # 3. Construct final proxies list with specific order:
                # - DIRECT/REJECT/🚀 节点选择 (built-ins / top priority) first
                # - Custom Nodes second
                # - Remaining existing proxies (nested groups, manual selections) third
                # - Airport Nodes last
                final_proxies = []
                custom_names = set(p.get("name") for p in custom_proxies if isinstance(p, dict) and p.get("name"))
                
                # Top priority items in exact order
                for top_item in ["DIRECT", "REJECT", "🚀 节点选择", "节点选择"]:
                    if top_item in existing_proxies and top_item not in final_proxies:
                        final_proxies.append(top_item)
                        
                for p in matched_candidates:
                    p_name = p.get("name")
                    if p_name and p_name in custom_names and p_name not in final_proxies:
                        final_proxies.append(p_name)
                        
                for ex_name in existing_proxies:
                    if ex_name and ex_name in valid_manual_proxies and ex_name not in final_proxies:
                        final_proxies.append(ex_name)
                        
                for p in matched_candidates:
                    p_name = p.get("name")
                    if p_name and p_name not in custom_names and p_name not in final_proxies:
                        final_proxies.append(p_name)
                        
                group["proxies"] = final_proxies
                
                # Clash will fail to start if a proxy group has neither 'use' nor a non-empty 'proxies' array.
                # Since we delete 'use' and 'filter', we must ensure 'proxies' is never empty.
                if not group["proxies"]:
                    group["proxies"] = ["DIRECT"]
                
                # Remove proxyforge-specific or mihomo-incompatible fields from the final output
                for field in ["include-all", "filter", "use"]:
                    if field in group:
                        del group[field]
        yaml_content = yaml.dump(template_config, allow_unicode=True, sort_keys=False)
        
        encoded_name = urllib.parse.quote(name)
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
            "Profile-Title": name
        }
        
        return PlainTextResponse(content=yaml_content, headers=headers)
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        logger.error(f"Subscription Generation Error: {error_msg}")
        return PlainTextResponse(content=f"Error generating subscription:\n{error_msg}", status_code=500)

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
            if proxies:
                save_cache_to_file(proxies)
                subscription_cache.clear()
                # 预热内存缓存，后续 /sub 请求将直接 0 延迟命中
                subscription_cache[hashkey()] = proxies
                logger.info(f"后台定时任务完成，成功更新了 {len(proxies)} 个机场节点")
            else:
                logger.warning("后台定时任务：拉取到的节点为空，放弃更新，保留旧缓存")
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
