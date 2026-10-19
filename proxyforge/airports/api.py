"""机场管理 Router；应用、鉴权、事务锁和 AirportService 均显式注入。"""
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import yaml

from proxyforge.airports.service import AirportService
from proxyforge.config.template_store import TemplateStore
from proxyforge.security.network_security import UnsafeOutboundUrl, validate_outbound_url
from proxyforge.subscription.builder import cleanup_proxy_group_references
from proxyforge.subscription.nodes import get_airport_name


class AirportsModel(BaseModel):
    # 保留旧 API 字符串/对象/未知字段及原始 400/422 边界。
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


@dataclass(frozen=True)
class AirportApi:
    """路由及同一组处理函数；供入口和内部 Python 工具显式绑定。"""
    router: APIRouter
    get_airports: Callable[[], dict]
    update_airports: Callable[[AirportsModel], dict]
    get_airports_info: Callable[..., dict]


def create_airport_router(*, verify_management: Callable,
                          configuration_lock: Callable[[], ContextManager],
                          sources_reader: Callable[[], List[Any]],
                          template_reader: Callable[[], str],
                          template_store: Callable[[], TemplateStore],
                          airport_service: AirportService,
                          service_errors: Callable[[Callable], Callable]) -> AirportApi:
    """只在应用装配时注册三个管理接口，不读取来源、环境或存储。"""
    router = APIRouter()

    @router.get("/api/airports", dependencies=[Depends(verify_management)])
    def get_airports():
        return {"urls": sources_reader()}

    @router.post("/api/airports", dependencies=[Depends(verify_management)])
    def update_airports(data: AirportsModel):
        with configuration_lock():
            check_airport_urls(data.urls)

            old_airports = sources_reader()
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
                    template_config = yaml.safe_load(template_reader()) or {}
                except yaml.YAMLError as e:
                    raise HTTPException(status_code=400, detail=f"无法清理机场引用，模板 YAML 错误: {e}")
                cleanup_result = cleanup_proxy_group_references(
                    template_config,
                    removed_provider_names=removed_provider_names,
                )
                if cleanup_result["total"]:
                    updates["template.yaml"] = yaml.safe_dump(template_config, allow_unicode=True, sort_keys=False)
            updates["airports.yaml"] = yaml.safe_dump(data.urls, allow_unicode=True, sort_keys=False)
            airport_service.invalidate_airport_cache(clear_disk=(old_airports != data.urls))
            snapshot = template_store().commit(updates, source="update_airports")
            return {"status": "ok", "cleanedReferences": cleanup_result["total"], "template_revision": snapshot["revision"]}

    @router.get("/api/airports/info", dependencies=[Depends(verify_management)])
    @service_errors
    def get_airports_info(force_indices: str = ""):
        return airport_service.get_airports_info(force_indices)

    return AirportApi(router, get_airports, update_airports, get_airports_info)
