import os
import yaml
import logging
from fastapi import FastAPI, HTTPException, Query, Header, Depends, Body
from fastapi.responses import PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import requests
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

def fetch_airport_proxies() -> List[Dict[str, Any]]:
    urls = load_airports()
    if not urls:
        logger.warning("未配置机场订阅链接，跳过拉取。")
        return []
        
    headers = {"User-Agent": "ClashForWindows/0.18.0"}
    all_proxies = []
    
    for url in urls:
        if not url.strip(): continue
        logger.info(f"正在从机场拉取节点: {url.strip()}")
        try:
            response = requests.get(url.strip(), headers=headers, timeout=10)
            response.raise_for_status()
            config = yaml.safe_load(response.text)
            if config and "proxies" in config and isinstance(config["proxies"], list):
                proxies = config["proxies"]
                logger.info(f"成功从 {url.strip()} 拉取到 {len(proxies)} 个节点")
                all_proxies.extend(proxies)
            else:
                logger.warning(f"机场订阅内容解析成功，但未找到 proxies 字段: {url.strip()}")
        except Exception as e:
            logger.error(f"拉取机场订阅失败 {url.strip()}: {e}")
            
    if not all_proxies and len([u for u in urls if u.strip()]) > 0:
        raise Exception("所有配置的机场订阅均拉取失败或无数据")
        
    return all_proxies

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
            for name in proxy_names:
                if name not in existing_proxies:
                    existing_proxies.append(name)
            group["proxies"] = existing_proxies

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
    
    # 因为去掉了机场链接，现在只需更新安全令牌和端口等（如果有）
    # 为保留文件中其他设置，简单读取重写
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
            continue # 删除旧的环境变量
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
    urls: List[str]

@app.post("/api/airports", dependencies=[Depends(verify_api_token)])
def update_airports(data: AirportsModel):
    save_airports(data.urls)
    # 更新了机场连接后，清空缓存
    subscription_cache.clear()
    return {"status": "ok"}

@app.get("/api/nodes", dependencies=[Depends(verify_api_token)])
def get_nodes():
    return {"nodes": load_custom_nodes()}

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
