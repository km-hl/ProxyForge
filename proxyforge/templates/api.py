"""模板 Router；鉴权、版本校验、共享事务与节点边界显式注入。"""
from dataclasses import dataclass
from typing import Any, Callable, ContextManager, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import yaml

from proxyforge.airports.service import AirportService
from proxyforge.config.network_config import validate_network_config, network_error_messages
from proxyforge.config.template_store import TemplateStore
from proxyforge.subscription.nodes import get_airport_name, strip_internal_proxy_fields
from proxyforge.subscription.validation import validate_mihomo_config, validate_proxy_nodes


class TemplateModel(BaseModel):
    content: str


class TemplateSaveModel(TemplateModel):
    expected_revision: str = None


class TemplateRestoreModel(BaseModel):
    expected_revision: str = None


class ImportModel(TemplateSaveModel):
    nodes: List[Dict[str, Any]]
    urls: List[Any]


@dataclass(frozen=True)
class TemplateApi:
    router: APIRouter
    get_template: Callable
    validate_template: Callable
    update_template: Callable
    template_history: Callable
    template_history_entry: Callable
    restore_template: Callable
    import_template: Callable


def create_template_router(*, verify_management: Callable,
                           configuration_lock: Callable[[], ContextManager],
                           template_store: Callable[[], TemplateStore],
                           revision_required: Callable, template_writer: Callable,
                           manual_nodes_reader: Callable, nodes_reader: Callable,
                           managed_nodes_reader: Callable, managed_names_reader: Callable,
                           sources_reader: Callable, manual_input: Callable,
                           validate_saved: Callable, validate_sources: Callable,
                           airport_service: AirportService) -> TemplateApi:
    """只注册七个管理接口，不读取存储，不另建事务锁或机场服务。"""
    router = APIRouter()

    @router.get("/api/template", dependencies=[Depends(verify_management)])
    def get_template():
        with configuration_lock():
            return template_store().snapshot()

    @router.post("/api/template/validate", dependencies=[Depends(verify_management)])
    def validate_template(data: TemplateModel):
        try:
            config = yaml.safe_load(data.content)
        except yaml.YAMLError:
            return {"errors": [{"code": "yaml_syntax", "path": "", "message": "YAML 语法错误，请检查缩进和字段"}],
                    "warnings": [], "info": [], "status": "error"}
        result = validate_network_config(config)
        errors = validate_mihomo_config(
            config,
            external_proxy_names=[node.get("name") for node in manual_nodes_reader() if isinstance(node, dict)] + managed_names_reader(),
            external_provider_names=[get_airport_name(item, index) for index, item in enumerate(sources_reader())],
            allow_internal_sources=True,
        )
        network_errors = set(network_error_messages(result))
        result["errors"].extend({"code": "template_invalid", "path": "", "message": message}
                                for message in errors if message not in network_errors)
        if result["errors"]:
            result["status"] = "error"
        return result

    @router.post("/api/template", dependencies=[Depends(verify_management)])
    def update_template(data: TemplateSaveModel):
        with configuration_lock():
            revision_required(data.expected_revision)
            validate_saved(data.content, nodes_reader(), sources_reader())
            return {"status": "ok", **template_writer(data.content)}

    @router.get("/api/template/history", dependencies=[Depends(verify_management)])
    def template_history():
        return {"entries": template_store().list_history()}

    @router.get("/api/template/history/{entry_id}", dependencies=[Depends(verify_management)])
    def template_history_entry(entry_id: str):
        try:
            return template_store().history_entry(entry_id)
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="History entry not found")

    @router.post("/api/template/history/{entry_id}/restore", dependencies=[Depends(verify_management)])
    def restore_template(entry_id: str, data: TemplateRestoreModel):
        with configuration_lock():
            revision_required(data.expected_revision)
            entry = template_history_entry(entry_id)
            validate_saved(entry["content"], nodes_reader(), sources_reader())
            return {"status": "ok", **template_store().commit(
                {"template.yaml": entry["content"]}, source="restore")}

    @router.post("/api/template/import", dependencies=[Depends(verify_management)])
    def import_template(data: ImportModel):
        with configuration_lock():
            revision_required(data.expected_revision)
            data.nodes = manual_input(data.nodes)
            errors = validate_proxy_nodes(data.nodes, location="nodes")
            if errors:
                raise HTTPException(status_code=400, detail={"message": "节点配置校验失败", "errors": errors})
            validate_sources(data.urls)
            validate_saved(data.content, data.nodes + managed_nodes_reader(), data.urls)
            airport_service.invalidate_airport_cache(clear_disk=(sources_reader() != data.urls))
            snapshot = template_store().commit({
                "template.yaml": data.content,
                "custom_nodes.yaml": yaml.safe_dump([strip_internal_proxy_fields(n) for n in data.nodes],
                                                    allow_unicode=True, sort_keys=False),
                "airports.yaml": yaml.safe_dump(data.urls, allow_unicode=True, sort_keys=False),
            }, source="import")
            return {"status": "ok", **snapshot}

    return TemplateApi(router, get_template, validate_template, update_template, template_history,
                       template_history_entry, restore_template, import_template)
