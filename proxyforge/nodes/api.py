"""节点管理 Router；存储、托管节点边界和机场聚合均由入口显式注入。"""
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import yaml

from proxyforge.config.template_store import TemplateStore
from proxyforge.subscription.links import parse_share_link
from proxyforge.subscription.nodes import strip_internal_proxy_fields
from proxyforge.subscription.validation import validate_proxy_nodes
from proxyforge.subscription.builder import cleanup_proxy_group_references


class ParseLinksModel(BaseModel):
    links: List[str]


class NodesModel(BaseModel):
    nodes: List[Dict[str, Any]]


@dataclass(frozen=True)
class NodeApi:
    router: APIRouter
    parse_links_api: Callable[[ParseLinksModel], dict]
    get_nodes: Callable[[], dict]
    get_all_proxies: Callable[[], dict]
    update_nodes: Callable[[NodesModel], dict]


def create_node_router(*, verify_management: Callable,
                       configuration_lock: Callable[[], ContextManager],
                       nodes_reader: Callable[[], List[Dict[str, Any]]],
                       airport_proxy_reader: Callable[[], List[Dict[str, Any]]],
                       manual_input: Callable[[list], list],
                       manual_nodes_reader: Callable[[], List[Dict[str, Any]]],
                       template_reader: Callable[[], str],
                       template_store: Callable[[], TemplateStore]) -> NodeApi:
    """只装配四个管理接口，不读取文件、数据库或启动网络任务。"""
    router = APIRouter()

    @router.post("/api/parse-links", dependencies=[Depends(verify_management)])
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

    @router.get("/api/nodes", dependencies=[Depends(verify_management)])
    def get_nodes():
        return {"nodes": nodes_reader()}

    @router.get("/api/proxies", dependencies=[Depends(verify_management)])
    def get_all_proxies():
        custom = nodes_reader()
        airports = airport_proxy_reader()
        return {"proxies": custom + airports}

    @router.post("/api/nodes", dependencies=[Depends(verify_management)])
    def update_nodes(data: NodesModel):
        with configuration_lock():
            data.nodes = manual_input(data.nodes)
            errors = validate_proxy_nodes(data.nodes, location="nodes")
            if errors:
                raise HTTPException(status_code=400, detail={"message": "节点配置校验失败", "errors": errors})
            old_names = {
                proxy.get("name") for proxy in manual_nodes_reader()
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
                    template_config = yaml.safe_load(template_reader()) or {}
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

    return NodeApi(router, parse_links_api, get_nodes, get_all_proxies, update_nodes)
