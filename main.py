from proxyforge.templates.api import (
    TemplateModel, TemplateSaveModel, TemplateRestoreModel, ImportModel, create_template_router,
)
from proxyforge.nodes.api import NodesModel, ParseLinksModel, create_node_router
from proxyforge.airports.service import AirportService, AirportSourcesChanged
from proxyforge.airports.api import AirportsModel, check_airport_urls, create_airport_router
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
from proxyforge.subscription.egern import build_egern_config
from proxyforge.subscription.egern_resources import load_rule_resource, resolve_provider_nodes
import os
import shutil
import yaml
import logging
import json
import urllib.parse
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from functools import wraps
from proxyforge.config.template_store import (
    TemplateStore, TemplateConflict, ConfigurationTooLarge, MAX_TEMPLATE_BYTES,
)
from proxyforge.control.control_store import ControlStore
from proxyforge.control.agent_api import attach_agent_routes
from fastapi import FastAPI, HTTPException, Query, Header, Depends, Body, Request
from fastapi.responses import PlainTextResponse, FileResponse, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
from dotenv import load_dotenv
from pydantic import BaseModel

from proxyforge.security.runtime_security import (
    ADMIN_TOKEN_MIN_LENGTH,
    INSECURE_DEFAULT_TOKENS,
    RuntimeConfigError,
    RuntimeConfigStore,
)
from proxyforge.security.network_security import safe_get
from proxyforge.security.auth_rate_limit import LoginRateLimiter
from proxyforge.config.network_config import validate_network_config, network_error_messages

# ================= 加载环境变量 =================
load_dotenv()
AIRPORT_CA_BUNDLE = os.environ.get("PROXYFORGE_AIRPORT_CA_BUNDLE", "").strip() or None
AIRPORT_BATCH_TIMEOUT = 180.0

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
            logger.error("初始化持久化模板失败（%s）", type(e).__name__)
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
        logger.error("迁移自建节点文件失败（%s）", type(e).__name__)
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

# ================= 核心读写逻辑 =================

def template_store():
    return TemplateStore(TEMPLATE_PATH, os.environ.get("TEMPLATE_HISTORY_LIMIT", "30"))


@contextmanager
def configuration_lock():
    try:
        with template_store().locked():
            yield
    except OSError:
        raise HTTPException(status_code=503, detail={"code": "storage_unavailable",
            "message": "存储暂不可用，提交状态待核对；请恢复存储后重新读取，勿直接重试覆盖"}) from None


def configuration_locked(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        with configuration_lock():
            return function(*args, **kwargs)
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
        logger.error("读取机场列表失败（%s）", type(e).__name__)
    return []

@configuration_locked
def save_airports(urls: List[str]):
    # Legacy initialization also participates in cache invalidation.
    airport_service.invalidate_airport_cache(clear_disk=True)
    with open(AIRPORTS_PATH, "w", encoding="utf-8") as f:
        yaml.dump(urls, f, allow_unicode=True, sort_keys=False)


# 一个实例统一协调来源更新、订阅请求、元信息请求和后台刷新。
airport_service = AirportService(
    sources_reader=lambda: load_airports(), cache_path=Path(CACHE_FILE_PATH).absolute(),
    info_cache_path=(Path(DATA_DIR) / "airports_info_cache.json").absolute(), http_get=safe_get,
    clock=time.time, monotonic=time.monotonic,
    configuration_lock=lambda: template_store().locked(), ca_bundle=AIRPORT_CA_BUNDLE,
    batch_timeout=AIRPORT_BATCH_TIMEOUT, logger=logger,
)


def airport_service_errors(function):
    """只映射服务错误，不持锁；网络请求期间仍允许配置提交。"""
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except AirportSourcesChanged:
            raise HTTPException(status_code=503, detail="机场配置正在更新，请稍后重试") from None
        except OSError:
            raise HTTPException(status_code=503, detail={"code": "storage_unavailable",
                "message": "存储暂不可用，提交状态待核对；请恢复存储后重新读取，勿直接重试覆盖"}) from None
    return wrapper


@airport_service_errors
def get_airport_proxies_cached(snapshot=None):
    return airport_service.get_airport_proxies_cached(snapshot)


@airport_service_errors
def subscription_airports():
    return airport_service.subscription_airports()


@airport_service_errors
def refresh_airport_cache(stop_event=None):
    return airport_service.refresh_airport_cache(stop_event)


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
        logger.error("读取自建节点文件失败（%s）", type(e).__name__)
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


@configuration_locked
def cleanup_runtime_template_references() -> Dict[str, Any]:
    content = load_template_content()
    if not content:
        return {"proxyReferences": [], "providerReferences": [], "total": 0}
    try:
        config = yaml.safe_load(content) or {}
    except yaml.YAMLError as e:
        logger.error("无法清理模板引用，YAML 格式错误（%s）", type(e).__name__)
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


# ================= 订阅下发接口 (对外公开) =================

@app.get("/egern/ruleset/{kind}", response_class=PlainTextResponse)
def get_egern_rule_set(kind: str, token: str = Query(...), value: str = Query(..., max_length=128),
                       revision: str = Query(None, max_length=64), no_resolve: bool = Query(False)):
    if token != SUBSCRIPTION_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        template = yaml.safe_load(load_template_content()) or {}
        content = load_rule_resource(kind, value, template.get('rule-providers') or {}, revision, no_resolve)
        return PlainTextResponse(content, headers={"Cache-Control": "no-store"})
    except ConfigValidationError as exc:
        return PlainTextResponse("规则集转换失败:\n- " + "\n- ".join(exc.errors), status_code=422)
    except Exception as exc:
        logger.warning("Egern 规则集请求失败（%s）", type(exc).__name__)
        return PlainTextResponse("规则集暂时不可用，请稍后重试", status_code=502)

@app.get("/provider/{airport_index}", response_class=PlainTextResponse)
@airport_service_errors
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
    proxies = airport_service.fetch_airport_item(airport, airport_index)
    if not proxies:
        source_name = get_airport_name(airport, airport_index).lower()
        proxies = [
            proxy for proxy in airport_service.load_cache_from_file()
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
    name: str = Query("ProxyForge", description="自定义订阅名称"),
    format: str = Query("clash", description="订阅格式：clash 或 egern")
):
    if token != SUBSCRIPTION_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if format not in {"clash", "egern"}:
        raise HTTPException(status_code=400, detail="不支持的订阅格式")

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
        skipped = 0
        if format == "egern":
            try:
                provider_nodes = resolve_provider_nodes(
                    final_config, airports, airport_proxies, str(request.base_url).rstrip('/'), token,
                    template_providers=template_config.get('proxy-providers'), ca_bundle=AIRPORT_CA_BUNDLE)
            except ConfigValidationError:
                raise
            except Exception as exc:
                logger.warning("Egern provider 请求失败（%s）", type(exc).__name__)
                raise HTTPException(status_code=502, detail="Egern 节点来源暂时不可用，请稍后重试") from None
            final_config, skipped = build_egern_config(final_config, provider_nodes, str(request.base_url), token)
        yaml_content = yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)
        if format == "egern":
            yaml_content = (f"# ProxyForge Egern：跳过 {skipped} 个不兼容节点；空代理组使用 REJECT。\n"
                            "# 节点、代理组和分流已转换；DNS/TUN 请在 Egern 中配置。\n" + yaml_content)

        encoded_name = urllib.parse.quote(name)
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
            "Profile-Title": encoded_name,
            "Cache-Control": "no-store",
            "ProxyForge-Skipped-Nodes": str(skipped),
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
    except Exception as exc:
        logger.error("订阅生成失败（%s）", type(exc).__name__)
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

# Router 与订阅/后台共用同一个服务、配置锁及存储工厂。
airport_api = create_airport_router(
    verify_management=verify_api_token, configuration_lock=configuration_lock,
    sources_reader=lambda: load_airports(), template_reader=lambda: load_template_content(),
    template_store=lambda: template_store(), airport_service=airport_service,
    service_errors=airport_service_errors,
)
app.include_router(airport_api.router)
# 保留已有内部 Python 调用名称，直接绑定同一处理函数，不注册重复路由。
get_airports = airport_api.get_airports
update_airports = airport_api.update_airports
get_airports_info = airport_api.get_airports_info


node_api = create_node_router(
    verify_management=verify_api_token, configuration_lock=configuration_lock,
    nodes_reader=lambda: load_custom_nodes(),
    airport_proxy_reader=lambda: get_airport_proxies_cached(),
    manual_input=lambda nodes: manual_node_input(nodes),
    manual_nodes_reader=lambda: load_manual_nodes(),
    template_reader=lambda: load_template_content(), template_store=lambda: template_store(),
)
app.include_router(node_api.router)
# 同一组实际处理函数，保留既有 Python 工具调用名称。
parse_links_api = node_api.parse_links_api
get_nodes = node_api.get_nodes
get_all_proxies = node_api.get_all_proxies
update_nodes = node_api.update_nodes


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


template_api = create_template_router(
    verify_management=verify_api_token, configuration_lock=configuration_lock,
    template_store=lambda: template_store(), revision_required=lambda value: require_revision(value),
    template_writer=lambda content: save_template_content(content),
    manual_nodes_reader=lambda: load_manual_nodes(), nodes_reader=lambda: load_custom_nodes(),
    managed_nodes_reader=lambda: managed_nodes(), managed_names_reader=lambda: managed_node_names(),
    sources_reader=lambda: load_airports(), manual_input=lambda nodes: manual_node_input(nodes),
    validate_saved=lambda content, nodes, airports: validate_saved_template(content, nodes, airports),
    validate_sources=lambda urls: check_airport_urls(urls), airport_service=airport_service,
)
app.include_router(template_api.router)
# 保留同一处理函数及请求模型的原 Python 名称。
get_template = template_api.get_template
validate_template = template_api.validate_template
update_template = template_api.update_template
template_history = template_api.template_history
template_history_entry = template_api.template_history_entry
restore_template = template_api.restore_template
import_template = template_api.import_template


import asyncio


def control_store():
    # No database initialization during import or subscription generation.
    return ControlStore(Path(DATA_DIR) / "proxyforge.db")


attach_agent_routes(app, verify_api_token, control_store)

# ================= 后台定时刷新任务 =================


AIRPORT_REFRESH_START_DELAY = 300
AIRPORT_REFRESH_INTERVAL = 4 * 3600
AIRPORT_REFRESH_SHUTDOWN_TIMEOUT = 5


class AirportUpdaterState:
    def __init__(self):
        self.stop = threading.Event()
        self.task = None
        self.worker = None
        self.thread_done = threading.Event()
        self.thread_done.set()


async def run_airport_refresh(state):
    def run():
        try:
            # Includes snapshot, network, fallback reads and guarded commits.
            refresh_airport_cache(state.stop)
        except Exception as exc:
            logger.error("后台定时任务异常（%s）", type(exc).__name__)
        finally:
            state.thread_done.set()

    try:
        await asyncio.to_thread(run)
    except Exception as exc:
        # Executor submission itself can fail before the thread starts.
        state.thread_done.set()
        logger.error("后台刷新线程启动失败（%s）", type(exc).__name__)


async def background_airport_updater(state):
    try:
        await asyncio.sleep(AIRPORT_REFRESH_START_DELAY)
        while not state.stop.is_set():
            logger.info("后台定时任务触发：开始静默拉取机场节点...")
            state.thread_done.clear()
            state.worker = asyncio.create_task(run_airport_refresh(state))
            # Cancelling the scheduler must not hide the still-running thread.
            await asyncio.shield(state.worker)
            if not state.stop.is_set():
                await asyncio.sleep(AIRPORT_REFRESH_INTERVAL)
    finally:
        state.stop.set()

@app.on_event("startup")
async def startup_event():
    previous = getattr(app.state, "airport_updater", None)
    if previous is not None:
        if previous.task is not None and not previous.task.done() and not previous.stop.is_set():
            return
        if not previous.thread_done.is_set():
            raise RuntimeError("Previous airport refresh is still stopping")
    await asyncio.to_thread(cleanup_runtime_template_references)
    state = AirportUpdaterState()
    app.state.airport_updater = state
    state.task = asyncio.create_task(background_airport_updater(state))
    logger.info("系统启动：已完成配置引用检查并注册后台定时更新任务")


@app.on_event("shutdown")
async def shutdown_event():
    state = getattr(app.state, "airport_updater", None)
    if state is None:
        return
    state.stop.set()
    state.task.cancel()
    await asyncio.gather(state.task, return_exceptions=True)
    if state.worker is not None and not state.worker.done():
        _, pending = await asyncio.wait({state.worker}, timeout=AIRPORT_REFRESH_SHUTDOWN_TIMEOUT)
        if pending:
            logger.warning("后台刷新仍在退出，已发出停止信号；等待中的线程未被强制终止")

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
