from proxyforge.subscription.links import parse_share_link
from proxyforge.subscription.nodes import (
    CUSTOM_NODES_SOURCE, strip_internal_proxy_fields, add_flag_to_proxy_name,
    get_airport_name, decorate_proxy_names,
)
from proxyforge.subscription.validation import (
    ConfigValidationError, validate_proxy_nodes, validate_mihomo_config, assert_valid_mihomo_config,
)
from proxyforge.subscription.builder import (
    build_airport_providers, build_airport_provider_document,
    cleanup_proxy_group_references, build_subscription_config,
)
import os
import shutil
import yaml
import logging
import base64
import json
import urllib.parse
import re
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from functools import wraps
from proxyforge.config.template_store import (
    TemplateStore, TemplateConflict, ConfigurationTooLarge, MAX_TEMPLATE_BYTES, sync_directory, atomic_write,
)
from proxyforge.control.control_store import ControlStore
from proxyforge.control.agent_api import attach_agent_routes
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Query, Header, Depends, Body, Request
from fastapi.responses import PlainTextResponse, FileResponse, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from cachetools import TTLCache
from typing import List, Dict, Any
from dotenv import load_dotenv
from pydantic import BaseModel

from proxyforge.security.runtime_security import (
    ADMIN_TOKEN_MIN_LENGTH,
    INSECURE_DEFAULT_TOKENS,
    RuntimeConfigError,
    RuntimeConfigStore,
)
from proxyforge.security.network_security import UnsafeOutboundUrl, safe_get, validate_outbound_url
from proxyforge.security.auth_rate_limit import LoginRateLimiter
from proxyforge.config.network_config import validate_network_config, network_error_messages

# ================= 加载环境变量 =================
load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR = "data"
RUNTIME_CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
ADMIN_BOOTSTRAP_PATH = os.path.join(DATA_DIR, "admin_token.txt")
SESSION_COOKIE_NAME = "proxyforge_session"
SESSION_TTL_SECONDS = 12 * 60 * 60

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True)

def get_env_var(key, default=""):
    return os.environ.get(key) or os.getenv(key, default)


RUNTIME_STORE = RuntimeConfigStore(RUNTIME_CONFIG_PATH, ADMIN_BOOTSTRAP_PATH)
try:
    RUNTIME_STORE.load_or_create()
except RuntimeConfigError as exc:
    logger.critical("读取持久化运行配置失败，拒绝不安全降级: %s", exc)
    raise

SUBSCRIPTION_TOKEN = RUNTIME_STORE.subscription_token
LOGIN_RATE_LIMITER = LoginRateLimiter()
if os.path.exists(ADMIN_BOOTSTRAP_PATH):
    logger.warning(
        "已生成独立管理密钥；请使用 docker compose exec proxyforge "
        "cat /app/data/admin_token.txt 读取，并登录后立即更换"
    )

TEMPLATE_PATH = os.path.join(DATA_DIR, "template.yaml")
TEMPLATE_EXAMPLE_PATH = "template.example.yaml"
LEGACY_TEMPLATE_PATH = "template.yaml"
CUSTOM_NODES_PATH = os.path.join(DATA_DIR, "custom_nodes.yaml")
LEGACY_CUSTOM_NODES_PATH = "custom_nodes.yaml"
CACHE_FILE_PATH = os.path.join(DATA_DIR, "airport_cache.yaml")
AIRPORTS_PATH = os.path.join(DATA_DIR, "airports.yaml")

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


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    if request.url.scheme == "https" or forwarded_scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

_subscription_cache = TTLCache(maxsize=1, ttl=12 * 60 * 60)
_subscription_cache_lock = threading.RLock()
_airport_cache_generation = 0
_airport_cache_sources = None
_airport_info_generation = 0
_airport_info_sequence = 0
_airport_info_accepted = {}

# ================= 核心读写逻辑 =================

def template_store():
    return TemplateStore(TEMPLATE_PATH, os.environ.get("TEMPLATE_HISTORY_LIMIT", "30"))


def configuration_locked(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            with template_store().locked():
                return function(*args, **kwargs)
        except OSError:
            raise HTTPException(status_code=503, detail={"code": "storage_unavailable",
                "message": "存储暂不可用，提交状态待核对；请恢复存储后重新读取，勿直接重试覆盖"})
    return wrapper


@app.exception_handler(TemplateConflict)
async def template_conflict_handler(request, exc):
    return JSONResponse(status_code=409, content={"detail": {
        "code": "template_conflict", "message": "模板已被其他会话修改",
        "current_revision": exc.current["revision"], "current_content": exc.current["content"]}})


@app.exception_handler(ConfigurationTooLarge)
async def configuration_size_handler(request, exc):
    return JSONResponse(status_code=413, content={"detail": "Configuration exceeds 1 MiB"})


def require_revision(value):
    if value is None:
        raise HTTPException(status_code=428, detail={"code": "revision_required",
                            "message": "请刷新页面读取模板版本后重试"})
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise HTTPException(status_code=422, detail="Invalid expected_revision")
    template_store().expect(value)


@configuration_locked
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

@configuration_locked
def save_airports(urls: List[str]):
    # Legacy initialization also participates in cache invalidation.
    invalidate_airport_cache(clear_disk=True)
    with open(AIRPORTS_PATH, "w", encoding="utf-8") as f:
        yaml.dump(urls, f, allow_unicode=True, sort_keys=False)


class AirportSourcesChanged(Exception):
    """A refresh no longer belongs to the active source/cache generation."""


@configuration_locked
def invalidate_airport_cache(*, clear_disk=False):
    global _airport_cache_generation, _airport_cache_sources, _airport_info_generation
    with _subscription_cache_lock:
        _airport_cache_generation += 1
        _subscription_cache.clear()
        if clear_disk:
            _airport_cache_sources = None
            _airport_info_generation += 1
            _airport_info_accepted.clear()
            # Remove before committing changed sources: a crash must not leave a
            # name-only disk cache belonging to a different URL after restart.
            for path in (Path(CACHE_FILE_PATH), Path(DATA_DIR) / "airports_info_cache.json"):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                else:
                    sync_directory(path.parent)


@configuration_locked
def airport_cache_snapshot():
    global _airport_cache_sources
    sources = load_airports()
    with _subscription_cache_lock:
        # Also notice configuration recovered from a previously committed redo
        # journal. Direct external writers are not a supported consistency API.
        if _airport_cache_sources is not None and _airport_cache_sources != sources:
            invalidate_airport_cache(clear_disk=True)
        _airport_cache_sources = deepcopy(sources)
        return deepcopy(sources), _airport_cache_generation


@contextmanager
def airport_cache_locked(snapshot):
    # Always take the configuration lock before the memory-cache lock. Never
    # perform network I/O in this context. Recovery runs before the source read.
    with template_store().locked():
        sources = load_airports()
        with _subscription_cache_lock:
            if snapshot[1] != _airport_cache_generation or snapshot[0] != sources:
                raise AirportSourcesChanged()
            yield

@configuration_locked
def load_manual_nodes() -> List[Dict[str, Any]]:
    initialize_custom_nodes_storage()
    if not os.path.exists(CUSTOM_NODES_PATH):
        return []
    try:
        with open(CUSTOM_NODES_PATH, "r", encoding="utf-8") as f:
            nodes = yaml.safe_load(f)
            if isinstance(nodes, list):
                for node in nodes:
                    if isinstance(node, dict):
                        node["_airport_name"] = CUSTOM_NODES_SOURCE
                return nodes
            return []
    except Exception as e:
        logger.error(f"读取自建节点文件失败: {e}")
    return []

def managed_nodes():
    # Preserve generation without a control-plane DB for standalone installations.
    if not (Path(DATA_DIR) / 'proxyforge.db').exists():
        return []
    return [{**node, '_airport_name': CUSTOM_NODES_SOURCE} for node in control_store().managed_nodes()]


def managed_node_names():
    if not (Path(DATA_DIR) / 'proxyforge.db').exists():
        return []
    return control_store().managed_node_names()


@configuration_locked
def load_custom_nodes() -> List[Dict[str, Any]]:
    return load_manual_nodes() + managed_nodes()


def manual_node_input(nodes):
    managed = {node['name']: node for node in managed_nodes()}
    manual = []
    for node in nodes:
        name = node.get('name', '') if isinstance(node, dict) else ''
        if name in managed and node == managed[name]:
            continue
        if (isinstance(node, dict) and '_managed_by' in node) or ' [pf:' in str(name):
            raise HTTPException(status_code=409, detail='Agent-managed nodes must be changed through their deployment')
        manual.append(node)
    return manual


def save_custom_nodes(nodes: List[Dict[str, Any]]):
    cleaned_nodes = [
        strip_internal_proxy_fields(node)
        for node in nodes
        if isinstance(node, dict)
    ]
    os.makedirs(os.path.dirname(CUSTOM_NODES_PATH), exist_ok=True)
    with open(CUSTOM_NODES_PATH, "w", encoding="utf-8") as f:
        yaml.dump(cleaned_nodes, f, allow_unicode=True, sort_keys=False)

@configuration_locked
def load_template_content() -> str:
    if not initialize_template_storage():
        return ""
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return f.read()

def save_template_content(content: str):
    return template_store().commit({"template.yaml": content})

def save_cache_to_file(proxies: List[Dict[str, Any]], snapshot):
    with airport_cache_locked(snapshot):
        try:
            content = yaml.dump(proxies, allow_unicode=True, sort_keys=False)
            atomic_write(CACHE_FILE_PATH, content)
        except Exception as e:
            logger.error("持久化节点缓存失败（%s）", type(e).__name__)

@configuration_locked
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


def fetch_airport_item(item: Any, index: int = 0) -> List[Dict[str, Any]]:
    url = item.get("url", "") if isinstance(item, dict) else item
    if not isinstance(url, str) or not url.strip():
        return []

    airport_name = get_airport_name(item, index)
    headers = {"User-Agent": "clash-verge/v1.6.0 clash-meta/1.18.3"}
    logger.info(f"正在从 {airport_name} 拉取节点")
    try:
        response = safe_get(url.strip(), headers=headers, timeout=30)
        response.raise_for_status()
        proxies = parse_airport_response(response.text)
        if proxies:
            for proxy in proxies:
                if isinstance(proxy, dict):
                    proxy["_airport_name"] = airport_name
            logger.info(f"成功从 {airport_name} 拉取到 {len(proxies)} 个节点")
            return proxies
        logger.warning(f"{airport_name} 订阅内容解析成功，但未找到代理节点")
    except Exception as e:
        logger.error(f"拉取 {airport_name} 订阅失败（{type(e).__name__}）")
    return []

def fetch_airport_proxies(sources=None) -> List[Dict[str, Any]]:
    urls_data = load_airports() if sources is None else sources
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

def fetch_single_airport_info(item) -> dict:
    """Fetch and parse only; the caller owns all cache reads and writes."""
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
        res = safe_get(url, headers=headers, timeout=30)
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
        info["error"] = type(e).__name__
        
    info["_timestamp"] = time.time()
    return info


@configuration_locked
def load_airport_info_cache():
    try:
        with open(Path(DATA_DIR) / "airports_info_cache.json", encoding="utf-8") as stream:
            data = json.load(stream)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, UnicodeError) as exc:
        logger.warning("读取机场信息缓存失败（%s）", type(exc).__name__)
        return {}
    if not isinstance(data, dict):
        logger.warning("机场信息缓存结构无效，重新获取")
        return {}
    valid = {}
    now = time.time()
    for url, entry in data.items():
        if not isinstance(entry, dict):
            continue
        stamp, info = entry.get("_timestamp"), entry.get("info")
        if (type(stamp) not in (int, float) or not 0 <= stamp <= now
                or not isinstance(info, dict) or info.get("url") != url
                or not isinstance(info.get("name"), str)
                or "error" not in info or not (info["error"] is None or isinstance(info["error"], str))
                or any(type(info.get(field)) is not int or info[field] < 0
                       for field in ("nodesCount", "upload", "download", "total", "expire"))):
            continue
        info["_timestamp"] = stamp
        valid[url] = entry
    if len(valid) != len(data):
        logger.warning("机场信息缓存包含无效条目，忽略损坏条目")
    return valid


@configuration_locked
def save_airport_info_cache(data):
    try:
        atomic_write(Path(DATA_DIR) / "airports_info_cache.json", json.dumps(data))
    except Exception as exc:
        logger.warning("持久化机场信息缓存失败（%s）", type(exc).__name__)


@configuration_locked
def cleanup_runtime_template_references() -> Dict[str, Any]:
    content = load_template_content()
    if not content:
        return {"proxyReferences": [], "providerReferences": [], "total": 0}
    try:
        config = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        logger.error(f"无法清理模板引用，YAML 格式错误: {e}")
        return {"proxyReferences": [], "providerReferences": [], "total": 0}

    custom_names = [
        proxy.get("name") for proxy in load_manual_nodes()
        if isinstance(proxy, dict) and proxy.get("name")
    ] + managed_node_names()
    provider_names = [
        get_airport_name(item, index) for index, item in enumerate(load_airports())
    ]
    result = cleanup_proxy_group_references(
        config,
        valid_proxy_names=custom_names,
        valid_provider_names=provider_names,
    )
    if result["total"]:
        save_template_content(yaml.safe_dump(config, allow_unicode=True, sort_keys=False))
        logger.warning(
            "已自动清理 %s 处失效代理组引用（节点 %s，机场 %s）",
            result["total"],
            len(result["proxyReferences"]),
            len(result["providerReferences"]),
        )
    return result


def get_airport_proxies_cached(snapshot=None) -> List[Dict[str, Any]]:
    if snapshot is None:
        for _ in range(2):
            try:
                return get_airport_proxies_cached(airport_cache_snapshot())
            except AirportSourcesChanged:
                continue
        raise HTTPException(status_code=503, detail="机场配置正在更新，请稍后重试")
    with airport_cache_locked(snapshot):
        cached = _subscription_cache.get(())
        if cached is not None:
            return deepcopy(cached)
    proxies = fetch_airport_proxies(snapshot[0])
    with airport_cache_locked(snapshot):
        # Another request may have filled the same generation while we fetched.
        cached = _subscription_cache.get(())
        if cached is None:
            cached = deepcopy(proxies)
            _subscription_cache[()] = cached
        return deepcopy(cached)


def subscription_airports():
    for _ in range(2):
        snapshot = airport_cache_snapshot()
        try:
            try:
                proxies = get_airport_proxies_cached(snapshot)
            except AirportSourcesChanged:
                raise
            except Exception as exc:
                logger.error("尝试使用本地持久化备份（%s）", type(exc).__name__)
                with airport_cache_locked(snapshot):
                    proxies = load_cache_from_file()
            with airport_cache_locked(snapshot):
                proxies, missing = merge_airport_proxies_with_cache(proxies, snapshot[0])
                if missing:
                    raise ConfigValidationError([
                        f"机场 [{source}] 当前未拉取到节点，且没有可用缓存" for source in missing
                    ])
                if proxies:
                    save_cache_to_file(proxies, snapshot)
                return snapshot[0], proxies
        except AirportSourcesChanged:
            continue
    raise HTTPException(status_code=503, detail="机场配置正在更新，请稍后重试")

# ================= 订阅下发接口 (对外公开) =================

@app.get("/provider/{airport_index}", response_class=PlainTextResponse)
def get_airport_provider(
    airport_index: int,
    token: str = Query(..., description="安全验证 Token"),
):
    if token != SUBSCRIPTION_TOKEN:
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
        content=yaml.safe_dump(
            build_airport_provider_document(output_proxies),
            allow_unicode=True,
            sort_keys=False,
        ),
    )

@app.get("/sub", response_class=PlainTextResponse)
def get_subscription(
    request: Request,
    token: str = Query(..., description="安全验证 Token"),
    name: str = Query("ProxyForge", description="自定义订阅名称")
):
    if token != SUBSCRIPTION_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        cleanup_runtime_template_references()
        airports, airport_proxies = subscription_airports()

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
            managed_references=managed_node_names(),
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

def set_management_session(response: Response, request: Request) -> None:
    forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    is_https = request.url.scheme == "https" or forwarded_scheme == "https"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=RUNTIME_STORE.create_session(SESSION_TTL_SECONDS),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=is_https,
        samesite="strict",
        path="/",
    )


def is_same_origin_request(request: Request) -> bool:
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return False
    try:
        supplied = urllib.parse.urlsplit(origin)
        expected = urllib.parse.urlsplit(str(request.base_url))
    except ValueError:
        return False

    def normalized_port(parsed, effective_scheme=None):
        if parsed.port is not None:
            return parsed.port
        scheme = effective_scheme or parsed.scheme
        return 443 if scheme == "https" else 80

    forwarded_scheme = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    expected_scheme = forwarded_scheme if forwarded_scheme in {"http", "https"} else expected.scheme
    return (
        supplied.scheme.lower() == expected_scheme.lower()
        and (supplied.hostname or "").lower() == (expected.hostname or "").lower()
        and normalized_port(supplied) == normalized_port(expected, expected_scheme)
    )


def verify_api_token(request: Request, authorization: str = Header(None)):
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    if session_token and RUNTIME_STORE.verify_session(session_token, SESSION_TTL_SECONDS):
        if request.method not in {"GET", "HEAD", "OPTIONS"} and not is_same_origin_request(request):
            raise HTTPException(status_code=403, detail="Cross-origin request rejected")
        return True

    if authorization and authorization.startswith("Bearer "):
        admin_token = authorization[len("Bearer "):].strip()
        if admin_token and RUNTIME_STORE.verify_admin_token(admin_token):
            return True

    raise HTTPException(status_code=401, detail="Invalid management credentials")

@app.post("/api/auth")
def auth_login(
    request: Request,
    response: Response,
    token: str = Body(..., embed=True),
):
    client_key = request.client.host if request.client else "unknown"
    retry_after = LOGIN_RATE_LIMITER.retry_after(client_key)
    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="登录失败次数过多，请稍后重试",
            headers={"Retry-After": str(retry_after)},
        )
    if not RUNTIME_STORE.verify_admin_token(token):
        LOGIN_RATE_LIMITER.record_failure(client_key)
        raise HTTPException(status_code=401, detail="Invalid management credentials")
    LOGIN_RATE_LIMITER.reset(client_key)
    set_management_session(response, request)
    return {"status": "ok"}


@app.get("/api/auth", dependencies=[Depends(verify_api_token)])
def auth_status():
    return {"status": "ok"}


@app.post("/api/logout", dependencies=[Depends(verify_api_token)])
def auth_logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="strict",
    )
    return {"status": "ok"}

@app.get("/api/config", dependencies=[Depends(verify_api_token)])
def get_config():
    return {
        "SUBSCRIPTION_TOKEN": SUBSCRIPTION_TOKEN
    }

class ConfigModel(BaseModel):
    SUBSCRIPTION_TOKEN: str

@app.post("/api/config", dependencies=[Depends(verify_api_token)])
def update_config(config: ConfigModel):
    global SUBSCRIPTION_TOKEN
    new_token = config.SUBSCRIPTION_TOKEN.strip()
    if len(new_token) < 16:
        raise HTTPException(status_code=400, detail="订阅密钥至少需要 16 个字符")
    if new_token in INSECURE_DEFAULT_TOKENS:
        raise HTTPException(status_code=400, detail="不能使用公开的默认 Token")

    try:
        RUNTIME_STORE.update_subscription_token(new_token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    SUBSCRIPTION_TOKEN = new_token

    return {"status": "ok"}


class AdminTokenModel(BaseModel):
    ADMIN_TOKEN: str


@app.post("/api/admin-token", dependencies=[Depends(verify_api_token)])
def update_admin_token(
    request: Request,
    response: Response,
    config: AdminTokenModel,
):
    new_token = config.ADMIN_TOKEN.strip()
    if len(new_token) < ADMIN_TOKEN_MIN_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"管理密钥至少需要 {ADMIN_TOKEN_MIN_LENGTH} 个字符",
        )
    if new_token in INSECURE_DEFAULT_TOKENS:
        raise HTTPException(status_code=400, detail="不能使用公开的默认管理密钥")

    try:
        RUNTIME_STORE.update_admin_token(new_token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    set_management_session(response, request)
    return {"status": "ok"}

@app.get("/api/airports", dependencies=[Depends(verify_api_token)])
def get_airports():
    return {"urls": load_airports()}

class AirportsModel(BaseModel):
    urls: List[Any]

def check_airport_urls(urls):
    for index, item in enumerate(urls, 1):
        url = item.get("url", "") if isinstance(item, dict) else item
        if not isinstance(url, str) or not url.strip():
            raise HTTPException(status_code=400, detail=f"机场 [{index}] 缺少订阅地址")
        try:
            validate_outbound_url(url)
        except UnsafeOutboundUrl as exc:
            raise HTTPException(
                status_code=400,
                detail=f"机场 [{index}] 订阅地址不安全: {exc}",
            ) from exc


@app.post("/api/airports", dependencies=[Depends(verify_api_token)])
@configuration_locked
def update_airports(data: AirportsModel):
    check_airport_urls(data.urls)

    old_airports = load_airports()
    new_provider_keys = {
        get_airport_name(item, index).lower() for index, item in enumerate(data.urls)
    }
    removed_provider_names = [
        get_airport_name(item, index) for index, item in enumerate(old_airports)
        if get_airport_name(item, index).lower() not in new_provider_keys
    ]
    updates = {}
    cleanup_result = {"proxyReferences": [], "providerReferences": [], "total": 0}
    if removed_provider_names:
        try:
            template_config = yaml.safe_load(load_template_content()) or {}
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"无法清理机场引用，模板 YAML 错误: {e}")
        cleanup_result = cleanup_proxy_group_references(
            template_config,
            removed_provider_names=removed_provider_names,
        )
        if cleanup_result["total"]:
            updates["template.yaml"] = yaml.safe_dump(template_config, allow_unicode=True, sort_keys=False)
    updates["airports.yaml"] = yaml.safe_dump(data.urls, allow_unicode=True, sort_keys=False)
    invalidate_airport_cache(clear_disk=(old_airports != data.urls))
    snapshot = template_store().commit(updates, source="update_airports")
    return {"status": "ok", "cleanedReferences": cleanup_result["total"], "template_revision": snapshot["revision"]}

@app.get("/api/airports/info", dependencies=[Depends(verify_api_token)])
def get_airports_info(force_indices: str = ""):
    global _airport_info_sequence
    force_idx_list = []
    if force_indices:
        try:
            force_idx_list = [int(x) for x in force_indices.split(",") if x.strip()]
        except ValueError:
            pass

    for _ in range(2):
        with template_store().locked():
            sources = deepcopy(load_airports())
            generation = _airport_info_generation
            _airport_info_sequence += 1
            sequence = _airport_info_sequence
            cached = load_airport_info_cache()
            urls = [(item.get("url", "") if isinstance(item, dict) else item).strip() for item in sources]
            force_urls = {url for i, url in enumerate(urls) if i in force_idx_list or force_indices == "all"}
            now = time.time()
            pending = list(dict.fromkeys(url for url in urls if url in force_urls or url not in cached
                                         or now - cached[url]["_timestamp"] >= 24 * 3600))

        # One fetch per URL, independent of aliases. No configuration/cache lock
        # is held during network I/O and workers never touch shared cache files.
        with ThreadPoolExecutor(max_workers=5) as executor:
            fetched = dict(zip(pending, executor.map(fetch_single_airport_info, pending)))

        with template_store().locked():
            if generation != _airport_info_generation or sources != load_airports():
                continue
            latest = load_airport_info_cache()
            # Re-read and merge only this request's fresh entries. A newer
            # accepted refresh wins even if its replace/directory fsync failed.
            entries = {url: value for url, value in latest.items() if url in urls}
            changed = False
            for url, info in fetched.items():
                if url and sequence > _airport_info_accepted.get(url, 0):
                    entries[url] = {"info": info, "_timestamp": info["_timestamp"]}
                    _airport_info_accepted[url] = sequence
                    changed = True
            if changed:
                save_airport_info_cache(entries)
            results = []
            for item, url in zip(sources, urls):
                # Prefer a concurrent committed refresh; if persistence failed,
                # still return the result acquired by this request.
                if url in fetched and _airport_info_accepted.get(url) == sequence:
                    info = fetched[url]
                elif url in entries:
                    info = entries[url]["info"]
                elif url in fetched:
                    info = fetched[url]
                else:
                    info = cached[url]["info"]
                info = deepcopy(info)
                if isinstance(item, dict) and item.get("name"):
                    info["name"] = item["name"]
                results.append(info)
            return {"info": results}
    raise HTTPException(status_code=503, detail="机场配置正在更新，请稍后重试")

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
@configuration_locked
def update_nodes(data: NodesModel):
    data.nodes = manual_node_input(data.nodes)
    errors = validate_proxy_nodes(data.nodes, location="nodes")
    if errors:
        raise HTTPException(status_code=400, detail={"message": "节点配置校验失败", "errors": errors})
    old_names = {
        proxy.get("name") for proxy in load_manual_nodes()
        if isinstance(proxy, dict) and proxy.get("name")
    }
    new_names = {
        proxy.get("name") for proxy in data.nodes
        if isinstance(proxy, dict) and proxy.get("name")
    }
    removed_names = old_names - new_names
    updates = {}
    cleanup_result = {"proxyReferences": [], "providerReferences": [], "total": 0}
    if removed_names:
        try:
            template_config = yaml.safe_load(load_template_content()) or {}
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"无法清理节点引用，模板 YAML 错误: {e}")
        cleanup_result = cleanup_proxy_group_references(
            template_config,
            removed_proxy_names=removed_names,
        )
        if cleanup_result["total"]:
            updates["template.yaml"] = yaml.safe_dump(template_config, allow_unicode=True, sort_keys=False)
    updates["custom_nodes.yaml"] = yaml.safe_dump([strip_internal_proxy_fields(n) for n in data.nodes], allow_unicode=True, sort_keys=False)
    snapshot = template_store().commit(updates, source="update_nodes")
    return {"status": "ok", "cleanedReferences": cleanup_result["total"], "template_revision": snapshot["revision"]}

@app.get("/api/template", dependencies=[Depends(verify_api_token)])
@configuration_locked
def get_template():
    return template_store().snapshot()

class TemplateModel(BaseModel):
    content: str


class TemplateSaveModel(TemplateModel):
    expected_revision: str = None


class TemplateRestoreModel(BaseModel):
    expected_revision: str = None


class ImportModel(TemplateSaveModel):
    nodes: List[Dict[str, Any]]
    urls: List[Any]


@app.post("/api/template/validate", dependencies=[Depends(verify_api_token)])
def validate_template(data: TemplateModel):
    try:
        config = yaml.safe_load(data.content)
    except yaml.YAMLError:
        return {"errors": [{"code": "yaml_syntax", "path": "", "message": "YAML 语法错误，请检查缩进和字段"}],
                "warnings": [], "info": [], "status": "error"}
    result = validate_network_config(config)
    errors = validate_mihomo_config(
        config,
        external_proxy_names=[node.get("name") for node in load_manual_nodes() if isinstance(node, dict)] + managed_node_names(),
        external_provider_names=[get_airport_name(item, index) for index, item in enumerate(load_airports())],
        allow_internal_sources=True,
    )
    network_errors = set(network_error_messages(result))
    result["errors"].extend({"code": "template_invalid", "path": "", "message": message}
                            for message in errors if message not in network_errors)
    if result["errors"]:
        result["status"] = "error"
    return result

@app.post("/api/template", dependencies=[Depends(verify_api_token)])
@configuration_locked
def update_template(data: TemplateSaveModel):
    require_revision(data.expected_revision)
    validate_saved_template(data.content, load_custom_nodes(), load_airports())
    return {"status": "ok", **save_template_content(data.content)}


def validate_saved_template(content, nodes, airports):
    if len(content.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise HTTPException(status_code=413, detail="Template exceeds 1 MiB")
    try:
        config = yaml.safe_load(content)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"YAML 格式错误: {e}")
    provider_names = [get_airport_name(item, index) for index, item in enumerate(airports)]
    custom_names = [
        proxy.get("name") for proxy in nodes
        if isinstance(proxy, dict) and proxy.get("name")
    ] + managed_node_names()
    errors = validate_mihomo_config(
        config,
        external_proxy_names=custom_names,
        external_provider_names=provider_names,
        allow_internal_sources=True,
    )
    if errors:
        raise HTTPException(status_code=400, detail={"message": "Mihomo 配置校验失败", "errors": errors})


@app.get("/api/template/history", dependencies=[Depends(verify_api_token)])
def template_history():
    return {"entries": template_store().list_history()}


@app.get("/api/template/history/{entry_id}", dependencies=[Depends(verify_api_token)])
def template_history_entry(entry_id: str):
    try:
        return template_store().history_entry(entry_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="History entry not found")


@app.post("/api/template/history/{entry_id}/restore", dependencies=[Depends(verify_api_token)])
@configuration_locked
def restore_template(entry_id: str, data: TemplateRestoreModel):
    require_revision(data.expected_revision)
    entry = template_history_entry(entry_id)
    validate_saved_template(entry["content"], load_custom_nodes(), load_airports())
    return {"status": "ok", **template_store().commit(
        {"template.yaml": entry["content"]}, source="restore")}


@app.post("/api/template/import", dependencies=[Depends(verify_api_token)])
@configuration_locked
def import_template(data: ImportModel):
    require_revision(data.expected_revision)
    data.nodes = manual_node_input(data.nodes)
    errors = validate_proxy_nodes(data.nodes, location="nodes")
    if errors:
        raise HTTPException(status_code=400, detail={"message": "节点配置校验失败", "errors": errors})
    check_airport_urls(data.urls)
    validate_saved_template(data.content, data.nodes + managed_nodes(), data.urls)
    invalidate_airport_cache(clear_disk=(load_airports() != data.urls))
    snapshot = template_store().commit({
        "template.yaml": data.content,
        "custom_nodes.yaml": yaml.safe_dump([strip_internal_proxy_fields(n) for n in data.nodes],
                                            allow_unicode=True, sort_keys=False),
        "airports.yaml": yaml.safe_dump(data.urls, allow_unicode=True, sort_keys=False),
    }, source="import")
    return {"status": "ok", **snapshot}


import asyncio


def control_store():
    # No database initialization during import or subscription generation.
    return ControlStore(Path(DATA_DIR) / "proxyforge.db")


attach_agent_routes(app, verify_api_token, control_store)

# ================= 后台定时刷新任务 =================

def refresh_airport_cache():
    snapshot = airport_cache_snapshot()
    proxies = fetch_airport_proxies(snapshot[0])
    try:
        with airport_cache_locked(snapshot):
            proxies, missing_sources = merge_airport_proxies_with_cache(proxies, snapshot[0])
            if proxies and not missing_sources:
                save_cache_to_file(proxies, snapshot)
                # Supersede in-flight foreground computations as well as the
                # previous cached value, without changing the source list.
                invalidate_airport_cache()
                _subscription_cache[()] = deepcopy(proxies)
                logger.info("后台定时任务完成，成功更新了 %s 个机场节点", len(proxies))
            else:
                logger.warning("后台定时任务：机场数据不完整，放弃覆盖旧缓存")
    except AirportSourcesChanged:
        logger.info("后台定时任务：来源已更新，丢弃旧刷新结果")


async def background_airport_updater():
    # 启动后先等待 5 分钟，错开刚启动时的并发请求
    await asyncio.sleep(300)
    while True:
        try:
            logger.info("后台定时任务触发：开始静默拉取机场节点...")
            refresh_airport_cache()
        except Exception as e:
            logger.error(f"后台定时任务异常: {e}")
            
        # 默认每隔 4 小时更新一次
        await asyncio.sleep(4 * 3600)

@app.on_event("startup")
async def startup_event():
    cleanup_runtime_template_references()
    logger.info("系统启动：已完成配置引用检查并注册后台定时更新任务")
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
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        access_log=False,
    )
