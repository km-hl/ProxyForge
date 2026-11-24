"""公开订阅 Router：显式注入动态密钥、共享服务和既有生成/资源回调。"""
from dataclasses import dataclass
import json
from typing import Callable, Optional
import urllib.parse

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.params import Param
from fastapi.responses import PlainTextResponse
import yaml

from .builder import build_airport_provider_document
from .links import render_uri_subscription
from .minimal_profile import (
    build_disabled_notice,
    build_info_notices,
    build_minimal_mihomo_config,
    detect_target_from_user_agent,
    select_and_personalize_user_proxies,
)
from .nodes import decorate_proxy_names, get_airport_name
from .singbox import build_singbox_config
from .surge import build_surge_config
from .validation import ConfigValidationError, validate_proxy_nodes


@dataclass(frozen=True)
class SubscriptionApi:
    router: APIRouter
    get_egern_rule_set: Callable
    get_airport_provider: Callable
    get_subscription: Callable


_TARGET_ALIASES = {
    'clash': 'mihomo',
    'mihomo': 'mihomo',
    'egern': 'egern',
    'singbox': 'singbox',
    'sing-box': 'singbox',
    'surge': 'surge',
    'uri': 'uri',
    'base64': 'uri',
}


def create_subscription_router(
    *,
    token_reader,
    template_reader,
    sources_reader,
    nodes_reader,
    managed_names_reader,
    references_cleaner,
    subscription_reader,
    airport_service,
    service_errors,
    rule_loader,
    config_builder,
    provider_resolver,
    egern_builder,
    ca_bundle_reader,
    logger,
    sub_users_resolver: Optional[Callable] = None,
    relay_resolver: Optional[Callable] = None,
    user_credentials_resolver: Optional[Callable] = None,
):
    """只装配公开订阅接口；不读取配置，不创建服务、缓存或全局 app。"""
    router = APIRouter()

    def _authenticate_token(supplied_token: str, *, allow_disabled_notice: bool = False):
        if supplied_token == token_reader():
            return None
        if sub_users_resolver is not None:
            auth_res = sub_users_resolver(supplied_token)
            if auth_res is not None:
                if not auth_res.get('authorized') and not allow_disabled_notice:
                    reason = auth_res.get('reason') or 'disabled'
                    detail = '订阅已过期或流量超出配额' if reason in ('expired', 'quota_exceeded') else '订阅已被停用'
                    headers = {'Cache-Control': 'no-store'}
                    if auth_res.get('userinfo'):
                        headers['Subscription-Userinfo'] = auth_res['userinfo']
                    raise HTTPException(status_code=403, detail=detail, headers=headers)
                return auth_res
        raise HTTPException(status_code=401, detail="Unauthorized")

    def _query_val(value):
        return value.default if isinstance(value, Param) else value

    def _resolve_providers(final_config, airports, airport_proxies, base_url, token, template_config, resolved_target):
        try:
            return provider_resolver(
                final_config,
                airports,
                airport_proxies,
                base_url,
                token,
                template_providers=template_config.get('proxy-providers'),
                ca_bundle=ca_bundle_reader(),
            )
        except ConfigValidationError:
            raise
        except Exception as exc:
            prefix = "Egern " if resolved_target == "egern" else "订阅"
            logger.warning("%sprovider 请求失败（%s）", prefix, type(exc).__name__)
            raise HTTPException(status_code=502, detail=f"{prefix}节点来源暂时不可用，请稍后重试") from None

    def _export_document(final_config, resolved_target, request, token, *, provider_nodes=None, raw_val=False):
        skipped = 0
        media_type = "text/plain; charset=utf-8"
        if resolved_target == "mihomo":
            body = yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)
        elif resolved_target == "egern":
            egern_doc, skipped = egern_builder(final_config, provider_nodes or {}, str(request.base_url), token)
            body = (
                f"# ProxyForge Egern：跳过 {skipped} 个不兼容节点；空代理组使用 REJECT。\n"
                "# 节点、代理组和分流已转换；DNS/TUN 请在 Egern 中配置。\n"
                + yaml.safe_dump(egern_doc, allow_unicode=True, sort_keys=False)
            )
        elif resolved_target == "singbox":
            sb_doc, skipped = build_singbox_config(final_config, provider_nodes or {})
            body = json.dumps(sb_doc, ensure_ascii=False, indent=2) + "\n"
            media_type = "application/json; charset=utf-8"
        elif resolved_target == "surge":
            body, skipped = build_surge_config(final_config, provider_nodes or {})
        else:
            all_nodes = list(final_config.get('proxies', []))
            for src_nodes in (provider_nodes or {}).values():
                all_nodes.extend(src_nodes)
            body, skipped = render_uri_subscription(all_nodes, encode_base64=not raw_val)
        return body, skipped, media_type

    def _build_response(body, media_type, skipped, name, user_auth):
        encoded_name = urllib.parse.quote(name)
        headers = {
            "Content-Disposition": f"attachment; filename*=UTF-8''{encoded_name}",
            "Profile-Title": encoded_name,
            "Cache-Control": "no-store",
            "ProxyForge-Skipped-Nodes": str(skipped),
        }
        if user_auth and user_auth.get('userinfo'):
            headers["Subscription-Userinfo"] = user_auth['userinfo']
        return PlainTextResponse(content=body, headers=headers, media_type=media_type)

    def _render_subscription(
        request: Request,
        token: str,
        name: str,
        fmt: Optional[str],
        target: Optional[str],
        prefer_relay: bool,
        raw: bool,
        *,
        auto_detect_ua: bool = False,
    ):
        user_auth = _authenticate_token(token, allow_disabled_notice=True)
        target_val = _query_val(target)
        fmt_val = _query_val(fmt)
        prefer_relay_val = bool(_query_val(prefer_relay))
        raw_val = bool(_query_val(raw))

        if target_val is not None:
            requested = str(target_val).strip().lower()
        elif fmt_val is not None:
            requested = str(fmt_val).strip().lower()
        elif auto_detect_ua and user_auth is not None:
            ua = request.headers.get('user-agent', '') if request is not None else ''
            requested = detect_target_from_user_agent(ua)
        else:
            requested = 'clash'

        resolved_target = _TARGET_ALIASES.get(requested)
        if not resolved_target:
            raise HTTPException(status_code=400, detail="不支持的订阅格式")

        user_meta = (user_auth or {}).get('user') or {}
        effective_prefer_relay = bool(prefer_relay_val or user_meta.get('prefer_relay'))

        try:
            # Multi-user disabled / expired / over-quota -> HTTP 200 single placeholder notice (zero real nodes leaked).
            if user_auth is not None and not user_auth.get('authorized'):
                notice_cfg = build_minimal_mihomo_config(
                    [],
                    disabled_notice=build_disabled_notice(user_auth.get('reason') or 'disabled'),
                )
                body, skipped, media_type = _export_document(
                    notice_cfg, resolved_target, request, token, provider_nodes={}, raw_val=raw_val
                )
                return _build_response(body, media_type, skipped, name, user_auth)

            # Multi-user minimal profile (selected managed/adopted/manual nodes, independent creds, no airports).
            # Preserve legacy template.yaml + allowed_groups path ONLY when allowed_nodes is empty & allowed_groups is set.
            allowed_nodes = user_meta.get('allowed_nodes') or []
            allowed_groups = user_meta.get('allowed_groups') or None
            if user_auth is not None and (allowed_nodes or not allowed_groups):
                custom_proxies = nodes_reader()
                relays = (relay_resolver() or []) if relay_resolver is not None else []
                creds_map = (
                    user_credentials_resolver(user_meta['id'], allowed_nodes)
                    if (user_credentials_resolver is not None and user_meta.get('id') and allowed_nodes)
                    else {}
                )
                selected = select_and_personalize_user_proxies(
                    custom_proxies,
                    allowed_nodes,
                    creds_map,
                    relays,
                    prefer_relay=effective_prefer_relay,
                )
                notices = build_info_notices(user_meta) if user_meta.get('info_nodes', True) else []
                minimal_cfg = build_minimal_mihomo_config(selected, info_notices=notices)
                body, skipped, media_type = _export_document(
                    minimal_cfg, resolved_target, request, token, provider_nodes={}, raw_val=raw_val
                )
                return _build_response(body, media_type, skipped, name, user_auth)

            # Admin main subscription (or legacy allowed_groups multi-user): full template.yaml + airports.
            references_cleaner()
            airports, airport_proxies = subscription_reader()
            custom_proxies = nodes_reader()

            template_content = template_reader()
            if not template_content:
                raise HTTPException(status_code=500, detail="Template file not found")
            template_config = yaml.safe_load(template_content) or {}

            # Airport nodes remain independent proxy-providers. Validate each node's
            # protocol fields here, while the provider endpoint validates its whole payload.
            airport_errors = []
            for index, airport_proxy in enumerate(airport_proxies, 1):
                airport_errors.extend(
                    validate_proxy_nodes([airport_proxy], location=f"airport-proxies[{index}]")
                )
            if airport_errors:
                raise ConfigValidationError(airport_errors)

            base_url = str(request.base_url).rstrip("/")
            builder_kwargs = {'managed_references': managed_names_reader()}
            if relay_resolver is not None:
                all_relays = relay_resolver() or []
                if effective_prefer_relay:
                    builder_kwargs['relays'] = all_relays
                    builder_kwargs['prefer_relay'] = True
                else:
                    marked_relays = [r for r in all_relays if isinstance(r, dict) and r.get('rewrite_subscription')]
                    if marked_relays:
                        builder_kwargs['relays'] = marked_relays
                        builder_kwargs['prefer_relay'] = True
            if allowed_groups:
                builder_kwargs['allowed_groups'] = allowed_groups

            final_config = config_builder(
                template_config,
                custom_proxies,
                airports,
                base_url,
                token,
                **builder_kwargs,
            )

            provider_nodes = {}
            if resolved_target != "mihomo":
                provider_nodes = _resolve_providers(
                    final_config, airports, airport_proxies, base_url, token, template_config, resolved_target
                )
            body, skipped, media_type = _export_document(
                final_config, resolved_target, request, token, provider_nodes=provider_nodes, raw_val=raw_val
            )
            return _build_response(body, media_type, skipped, name, user_auth)
        except ConfigValidationError as e:
            logger.warning("订阅配置校验失败（%s 项错误）", len(e.errors))
            return PlainTextResponse(
                content="订阅配置校验失败:\n- " + "\n- ".join(e.errors),
                status_code=422,
            )
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("订阅生成失败（%s）", type(exc).__name__)
            return PlainTextResponse(content="生成订阅时发生内部错误，请查看服务端日志。", status_code=500)

    @router.get("/egern/ruleset/{kind}", response_class=PlainTextResponse)
    def get_egern_rule_set(kind: str, token: str = Query(...), value: str = Query(..., max_length=128),
                           revision: str = Query(None, max_length=64), no_resolve: bool = Query(False)):
        _authenticate_token(token)
        try:
            template = yaml.safe_load(template_reader()) or {}
            content = rule_loader(kind, value, template.get('rule-providers') or {}, revision, no_resolve)
            return PlainTextResponse(content, headers={"Cache-Control": "no-store"})
        except ConfigValidationError as exc:
            return PlainTextResponse("规则集转换失败:\n- " + "\n- ".join(exc.errors), status_code=422)
        except Exception as exc:
            logger.warning("Egern 规则集请求失败（%s）", type(exc).__name__)
            return PlainTextResponse("规则集暂时不可用，请稍后重试", status_code=502)

    @router.get("/provider/{airport_index}", response_class=PlainTextResponse)
    @service_errors
    def get_airport_provider(
        airport_index: int,
        token: str = Query(..., description="安全验证 Token"),
    ):
        _authenticate_token(token)
        airports = sources_reader()
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

    @router.get("/sub", response_class=PlainTextResponse)
    def get_subscription(
        request: Request,
        token: str = Query(..., description="安全验证 Token"),
        name: str = Query("ProxyForge", description="自定义订阅名称"),
        format: str = Query("clash", description="兼容订阅格式：clash|egern|singbox|surge|uri"),
        target: Optional[str] = Query(None, description="目标客户端：mihomo|singbox|surge|egern|uri"),
        prefer_relay: bool = Query(False, description="中转优先重写入口地址"),
        raw: bool = Query(False, description="URI 格式是否输出明文逐行"),
    ):
        return _render_subscription(request, token, name, format, target, prefer_relay, raw)

    if sub_users_resolver is not None:
        @router.get("/sub/{user_token}", response_class=PlainTextResponse)
        def get_user_subscription(
            request: Request,
            user_token: str,
            name: str = Query("ProxyForge", description="自定义订阅名称"),
            format: Optional[str] = Query(None, description="兼容订阅格式：clash|egern|singbox|surge|uri"),
            target: Optional[str] = Query(None, description="目标客户端：mihomo|singbox|surge|egern|uri"),
            prefer_relay: bool = Query(False, description="中转优先重写入口地址"),
            raw: bool = Query(False, description="URI 格式是否输出明文逐行"),
        ):
            return _render_subscription(
                request, user_token, name, format, target, prefer_relay, raw, auto_detect_ua=True
            )

    return SubscriptionApi(router, get_egern_rule_set, get_airport_provider, get_subscription)
