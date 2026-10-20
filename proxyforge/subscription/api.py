"""公开订阅 Router：显式注入动态密钥、共享服务和既有生成/资源回调。"""
from dataclasses import dataclass
from typing import Callable
import urllib.parse

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
import yaml

from .builder import build_airport_provider_document
from .nodes import decorate_proxy_names, get_airport_name
from .validation import ConfigValidationError, validate_proxy_nodes


@dataclass(frozen=True)
class SubscriptionApi:
    router: APIRouter
    get_egern_rule_set: Callable
    get_airport_provider: Callable
    get_subscription: Callable


def create_subscription_router(*, token_reader, template_reader, sources_reader, nodes_reader,
                               managed_names_reader, references_cleaner, subscription_reader,
                               airport_service, service_errors, rule_loader, config_builder,
                               provider_resolver, egern_builder, ca_bundle_reader, logger):
    """只装配三个公开接口；不读取配置，不创建服务、缓存或全局 app。"""
    router = APIRouter()

    @router.get("/egern/ruleset/{kind}", response_class=PlainTextResponse)
    def get_egern_rule_set(kind: str, token: str = Query(...), value: str = Query(..., max_length=128),
                           revision: str = Query(None, max_length=64), no_resolve: bool = Query(False)):
        if token != token_reader():
            raise HTTPException(status_code=401, detail="Unauthorized")
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
        if token != token_reader():
            raise HTTPException(status_code=401, detail="Unauthorized")
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
        format: str = Query("clash", description="订阅格式：clash 或 egern")
    ):
        if token != token_reader():
            raise HTTPException(status_code=401, detail="Unauthorized")
        if format not in {"clash", "egern"}:
            raise HTTPException(status_code=400, detail="不支持的订阅格式")

        try:
            references_cleaner()
            airports, airport_proxies = subscription_reader()

            custom_proxies = nodes_reader()

            template_content = template_reader()
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
            final_config = config_builder(
                template_config,
                custom_proxies,
                airports,
                str(request.base_url).rstrip("/"),
                token,
                managed_references=managed_names_reader(),
            )
            skipped = 0
            if format == "egern":
                try:
                    provider_nodes = provider_resolver(
                        final_config, airports, airport_proxies, str(request.base_url).rstrip('/'), token,
                        template_providers=template_config.get('proxy-providers'), ca_bundle=ca_bundle_reader())
                except ConfigValidationError:
                    raise
                except Exception as exc:
                    logger.warning("Egern provider 请求失败（%s）", type(exc).__name__)
                    raise HTTPException(status_code=502, detail="Egern 节点来源暂时不可用，请稍后重试") from None
                final_config, skipped = egern_builder(final_config, provider_nodes, str(request.base_url), token)
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

    return SubscriptionApi(router, get_egern_rule_set, get_airport_provider, get_subscription)
