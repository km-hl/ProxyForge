import os
import yaml
import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
import requests
from cachetools import cached, TTLCache
from typing import List, Dict, Any
from dotenv import load_dotenv

# ================= 加载环境变量 =================
load_dotenv()

# ================= 配置区域 =================
# 从 .env 读取（如果没有配置则使用默认值）
AIRPORT_SUB_URL = os.getenv("AIRPORT_SUB_URL", "")
SECRET_TOKEN = os.getenv("SECRET_TOKEN", "my_secret_token")

TEMPLATE_PATH = "template.yaml"
CUSTOM_NODES_PATH = "custom_nodes.yaml"
DATA_DIR = "data"
CACHE_FILE_PATH = os.path.join(DATA_DIR, "airport_cache.yaml")

# 确保数据持久化目录存在
os.makedirs(DATA_DIR, exist_ok=True)

# ================= 日志配置 =================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ================= FastAPI 实例 =================
app = FastAPI(title="ProxyForge", description="专属节点订阅聚合与配置下发中心")

# ================= 缓存配置 =================
# 内存缓存，TTL 为 12 小时
subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60)

def load_custom_nodes() -> List[Dict[str, Any]]:
    """实时加载自建节点文件"""
    if not os.path.exists(CUSTOM_NODES_PATH):
        return []
    try:
        with open(CUSTOM_NODES_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            if isinstance(nodes, list):
                return nodes
    except Exception as e:
        logger.error(f"读取自建节点文件失败: {e}")
    return []

def save_cache_to_file(proxies: List[Dict[str, Any]]):
    """将拉取成功的机场节点持久化到本地文件"""
    try:
        with open(CACHE_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.dump(proxies, f, allow_unicode=True, sort_keys=False)
    except Exception as e:
        logger.error(f"持久化节点缓存失败: {e}")

def load_cache_from_file() -> List[Dict[str, Any]]:
    """从本地持久化文件加载最近一次成功的机场节点"""
    if not os.path.exists(CACHE_FILE_PATH):
        return []
    try:
        with open(CACHE_FILE_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            if isinstance(nodes, list):
                logger.info(f"从本地持久化缓存加载了 {len(nodes)} 个机场节点")
                return nodes
    except Exception as e:
        logger.error(f"读取节点持久化缓存失败: {e}")
    return []

def fetch_airport_proxies() -> List[Dict[str, Any]]:
    """拉取机场订阅并解析出 proxies 列表"""
    if not AIRPORT_SUB_URL:
        logger.warning("未配置 AIRPORT_SUB_URL，跳过机场拉取。")
        return []

    headers = {"User-Agent": "ClashForWindows/0.18.0"}
    logger.info(f"正在从机场拉取节点: {AIRPORT_SUB_URL}")
    try:
        response = requests.get(AIRPORT_SUB_URL, headers=headers, timeout=10)
        response.raise_for_status()
        
        config = yaml.safe_load(response.text)
        if config and "proxies" in config and isinstance(config["proxies"], list):
            proxies = config["proxies"]
            logger.info(f"成功拉取到 {len(proxies)} 个机场节点")
            return proxies
        else:
            logger.warning("机场订阅内容解析成功，但未找到 proxies 字段")
            return []
    except Exception as e:
        logger.error(f"拉取机场订阅失败: {e}")
        raise

@cached(cache=subscription_cache)
def get_airport_proxies_cached() -> List[Dict[str, Any]]:
    """带 TTL 缓存的拉取函数"""
    return fetch_airport_proxies()

@app.get("/sub", response_class=PlainTextResponse)
def get_subscription(token: str = Query(..., description="安全验证 Token")):
    """获取合并后的订阅配置"""
    if token != SECRET_TOKEN:
        logger.warning(f"拒绝未授权的访问，错误的 token: {token}")
        raise HTTPException(status_code=401, detail="Unauthorized")

    airport_proxies = []

    # 1. 获取机场节点（带容错处理）
    try:
        airport_proxies = get_airport_proxies_cached()
        if airport_proxies:
            save_cache_to_file(airport_proxies)  # 成功则保存到文件备份
    except Exception:
        logger.error("无法获取最新的机场数据，尝试使用本地持久化备份...")
        airport_proxies = load_cache_from_file()

    # 2. 获取自建节点
    custom_proxies = load_custom_nodes()

    # 3. 数据合并
    all_proxies = airport_proxies + custom_proxies
    logger.info(f"合并后总节点数: {len(all_proxies)} (机场: {len(airport_proxies)}, 自建: {len(custom_proxies)})")
    
    proxy_names = [p["name"] for p in all_proxies]

    # 4. 模板注入
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

    # 5. 返回 YAML
    return yaml.dump(template_config, allow_unicode=True, sort_keys=False)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
