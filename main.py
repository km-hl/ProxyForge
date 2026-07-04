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

# 全局变量
AIRPORT_SUB_URL = get_env_var("AIRPORT_SUB_URL", "")
SECRET_TOKEN = get_env_var("SECRET_TOKEN", "my_secret_token")

TEMPLATE_PATH = "template.yaml"
CUSTOM_NODES_PATH = "custom_nodes.yaml"
DATA_DIR = "data"
CACHE_FILE_PATH = os.path.join(DATA_DIR, "airport_cache.yaml")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True) # 确保 static 目录存在

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="ProxyForge", description="专属节点订阅聚合与配置下发中心")

subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60)

# ================= 核心读写逻辑 =================

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
    if not AIRPORT_SUB_URL:
        return []
    headers = {"User-Agent": "ClashForWindows/0.18.0"}
    try:
        response = requests.get(AIRPORT_SUB_URL, headers=headers, timeout=10)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
        if config and "proxies" in config and isinstance(config["proxies"], list):
            return config["proxies"]
    except Exception as e:
        logger.error(f"拉取机场订阅失败: {e}")
        raise
    return []

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
    except Exception:
        airport_proxies = load_cache_from_file()

    custom_proxies = load_custom_nodes()
    all_proxies = airport_proxies + custom_proxies
    proxy_names = [p["name"] for p in all_proxies]

    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(status_code=500, detail="Template file not found")

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template_config = yaml.safe_load(f) or {}

    template_config["proxies"] = all_proxies

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
        "AIRPORT_SUB_URL": AIRPORT_SUB_URL,
        "SECRET_TOKEN": SECRET_TOKEN
    }

class ConfigModel(BaseModel):
    AIRPORT_SUB_URL: str
    SECRET_TOKEN: str

@app.post("/api/config", dependencies=[Depends(verify_api_token)])
def update_config(config: ConfigModel):
    global AIRPORT_SUB_URL, SECRET_TOKEN
    # 为了简化，直接重写 .env 文件
    env_content = f'AIRPORT_SUB_URL="{config.AIRPORT_SUB_URL}"\nSECRET_TOKEN="{config.SECRET_TOKEN}"\n'
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(env_content)
    
    AIRPORT_SUB_URL = config.AIRPORT_SUB_URL
    SECRET_TOKEN = config.SECRET_TOKEN
    os.environ["AIRPORT_SUB_URL"] = AIRPORT_SUB_URL
    os.environ["SECRET_TOKEN"] = SECRET_TOKEN
    
    # 清除缓存以便立即生效
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
