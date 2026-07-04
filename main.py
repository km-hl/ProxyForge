import os
import yaml
import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
import requests
from cachetools import cached, TTLCache
from typing import List, Dict, Any

# ================= 配置区域 =================
# 机场订阅链接（替换为你的实际订阅链接）
AIRPORT_SUB_URL = os.getenv("AIRPORT_SUB_URL", "https://example.com/sub")

# 安全验证 Token
SECRET_TOKEN = os.getenv("SECRET_TOKEN", "my_secret_token")

# 自建节点列表（此处为示例，可根据实际情况修改）
MY_CUSTOM_PROXIES = [
    {
        "name": "🇺🇸 自建 US-1",
        "type": "ss",
        "server": "1.2.3.4",
        "port": 8388,
        "cipher": "aes-256-gcm",
        "password": "password"
    },
    {
        "name": "🇭🇰 自建 HK-1",
        "type": "vmess",
        "server": "5.6.7.8",
        "port": 443,
        "uuid": "uuid-string",
        "alterId": 0,
        "cipher": "auto",
        "tls": True
    }
]

# 模板文件路径
TEMPLATE_PATH = "template.yaml"

# ================= 日志配置 =================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ================= FastAPI 实例 =================
app = FastAPI(title="ProxyForge", description="专属节点订阅聚合与配置下发中心")

# ================= 缓存配置 =================
# 使用 TTLCache，最大缓存 1 个元素（因为只有一份订阅），TTL 为 12 小时（43200 秒）
subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60)

# 保留一份持久的最后一次成功拉取的备份，以防缓存过期后拉取机场失败时作为回退（Fallback）
last_successful_proxies: List[Dict[str, Any]] = []

def fetch_airport_proxies() -> List[Dict[str, Any]]:
    """
    拉取机场订阅并解析出 proxies 列表
    """
    headers = {
        "User-Agent": "ClashForWindows/0.18.0"  # 伪装为 Clash 客户端，让机场直接返回 YAML 格式
    }
    logger.info(f"正在从机场拉取节点: {AIRPORT_SUB_URL}")
    try:
        response = requests.get(AIRPORT_SUB_URL, headers=headers, timeout=10)
        response.raise_for_status()
        
        # 解析 YAML
        config = yaml.safe_load(response.text)
        if config and "proxies" in config and isinstance(config["proxies"], list):
            proxies = config["proxies"]
            logger.info(f"成功拉取到 {len(proxies)} 个机场节点")
            return proxies
        else:
            logger.warning("机场订阅内容解析成功，但未找到 proxies 字段或格式错误")
            return []
    except Exception as e:
        logger.error(f"拉取机场订阅失败: {e}")
        raise

@cached(cache=subscription_cache)
def get_airport_proxies_cached() -> List[Dict[str, Any]]:
    """
    带缓存的机场节点获取函数
    如果拉取失败且缓存已失效，会抛出异常，外层捕获后可以使用 fallback 数据
    """
    return fetch_airport_proxies()

@app.get("/sub", response_class=PlainTextResponse)
def get_subscription(token: str = Query(..., description="安全验证 Token")):
    """
    获取合并后的订阅配置，返回纯文本 YAML
    """
    global last_successful_proxies

    # 1. 安全验证
    if token != SECRET_TOKEN:
        logger.warning(f"拒绝未授权的访问，错误的 token: {token}")
        raise HTTPException(status_code=401, detail="Unauthorized")

    airport_proxies = []

    # 2. 获取机场节点（带容错处理）
    try:
        # 尝试从缓存或网络获取节点
        airport_proxies = get_airport_proxies_cached()
        # 成功获取后，更新最后的成功备份
        last_successful_proxies = airport_proxies
    except Exception:
        logger.error("无法获取最新的机场节点数据，尝试使用最后一次成功的备份。")
        if last_successful_proxies:
            logger.info("使用最后一次成功的备份数据。")
            airport_proxies = last_successful_proxies
        else:
            logger.warning("没有可用的备份数据，将仅使用自建节点。")
            airport_proxies = []

    # 3. 数据合并
    all_proxies = airport_proxies + MY_CUSTOM_PROXIES
    logger.info(f"合并后总节点数: {len(all_proxies)} (机场: {len(airport_proxies)}, 自建: {len(MY_CUSTOM_PROXIES)})")
    
    # 获取所有节点名称，用于注入策略组
    proxy_names = [p["name"] for p in all_proxies]

    # 4. 模板注入
    if not os.path.exists(TEMPLATE_PATH):
        logger.error(f"模板文件 {TEMPLATE_PATH} 不存在！")
        raise HTTPException(status_code=500, detail="Template file not found")

    try:
        with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
            template_config = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"读取或解析模板文件失败: {e}")
        raise HTTPException(status_code=500, detail="Failed to load template file")

    # 确保 template_config 是一个字典
    if not isinstance(template_config, dict):
        template_config = {}

    # 注入 proxies 列表
    template_config["proxies"] = all_proxies

    # 注入 proxy-groups 策略组
    if "proxy-groups" in template_config and isinstance(template_config["proxy-groups"], list):
        for group in template_config["proxy-groups"]:
            existing_proxies = group.get("proxies", [])
            if existing_proxies is None:
                existing_proxies = []
            
            # 将合并后的所有节点名称加入（避免重复加入，保持原始项如 DIRECT 在前）
            for name in proxy_names:
                if name not in existing_proxies:
                    existing_proxies.append(name)
            
            group["proxies"] = existing_proxies

    # 5. API 输出
    # 将字典转回 YAML 字符串
    # allow_unicode=True 保证中文字符不被转义，sort_keys=False 保持键的原始顺序
    final_yaml = yaml.dump(template_config, allow_unicode=True, sort_keys=False)
    
    return final_yaml

if __name__ == "__main__":
    import uvicorn
    # 本地开发测试可以直接运行 main.py
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
