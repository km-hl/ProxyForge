"""Unified subscription node ordering persistence, sorting helpers, and management router."""
import json
import os
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, constr
import yaml

from proxyforge.config.template_store import atomic_write
from proxyforge.subscription.nodes import strip_internal_proxy_fields

MAX_ORDER_ITEMS = 1000


def node_sort_key(node: Any) -> str:
    """Return an immutable sorting key for a subscription node."""
    if not isinstance(node, dict):
        return ""
    managed = node.get("_managed_by")
    if isinstance(managed, dict):
        if managed.get("deployment_id"):
            return f"agent:{managed['deployment_id']}"
        if managed.get("chain_id"):
            return f"chain:{managed['chain_id']}"
        if managed.get("adoption_id"):
            return f"adopted:{managed['adoption_id']}"
    name = str(node.get("name") or "").strip()
    return f"manual:{name}" if name else ""


def node_source_kind(node: Any) -> str:
    """Return a non-secret source classification for UI display."""
    if not isinstance(node, dict):
        return "manual"
    managed = node.get("_managed_by")
    if isinstance(managed, dict):
        if managed.get("chain_id"):
            return "chain"
        if managed.get("adoption_id") or managed.get("type") == "adopted":
            return "adopted"
        return "agent"
    return "manual"


def _normalize_order_list(order: Any) -> List[str]:
    if not isinstance(order, list):
        return []
    seen = set()
    cleaned: List[str] = []
    for raw in order:
        if not isinstance(raw, str):
            continue
        item = raw.strip()
        if not item or len(item) > 256 or item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    return cleaned


def apply_node_order(nodes: List[Dict[str, Any]], order: List[str]) -> List[Dict[str, Any]]:
    """Sort subscription nodes stably according to saved keys; unknown nodes stay at the end."""
    cleaned = _normalize_order_list(order)
    if not cleaned:
        return list(nodes)
    rank = {key: idx for idx, key in enumerate(cleaned)}
    fallback_base = len(cleaned)
    indexed = list(enumerate(nodes))
    indexed.sort(key=lambda pair: (rank.get(node_sort_key(pair[1]), fallback_base + pair[0]), pair[0]))
    return [pair[1] for pair in indexed]


def sync_manual_order_in_saved_order(saved_order: List[str], manual_names: List[str]) -> List[str]:
    """Update `manual:*` entries in a saved mixed order after manual nodes are edited/reordered."""
    cleaned = _normalize_order_list(saved_order)
    if not cleaned:
        return []
    new_manual = _normalize_order_list([f"manual:{str(n).strip()}" for n in manual_names if str(n or "").strip()])
    manual_iter = iter(new_manual)
    updated: List[str] = []
    last_manual_pos = -1
    for key in cleaned:
        if key.startswith("manual:"):
            nxt = next(manual_iter, None)
            if nxt is not None:
                updated.append(nxt)
                last_manual_pos = len(updated)
        else:
            updated.append(key)
    leftover = list(manual_iter)
    if leftover:
        insert_at = last_manual_pos if last_manual_pos >= 0 else len(updated)
        updated[insert_at:insert_at] = leftover
    return _normalize_order_list(updated)


def sync_manual_nodes_file_order(manual_nodes: List[Dict[str, Any]], order: List[str]) -> List[Dict[str, Any]]:
    """Reorder manual nodes cleanly according to the relative `manual:*` positions in `order`."""
    cleaned = _normalize_order_list(order)
    if not cleaned or not manual_nodes:
        return list(manual_nodes)
    manual_rank: Dict[str, int] = {}
    seq = 0
    for key in cleaned:
        if key.startswith("manual:"):
            manual_rank[key] = seq
            seq += 1
    if not manual_rank:
        return list(manual_nodes)
    indexed = list(enumerate(manual_nodes))
    indexed.sort(key=lambda pair: (manual_rank.get(node_sort_key(pair[1]), seq + pair[0]), pair[0]))
    return [pair[1] for pair in indexed]


def load_node_order(path: Path) -> List[str]:
    target = Path(path)
    if not target.exists():
        return []
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    if isinstance(payload, dict):
        return _normalize_order_list(payload.get("order"))
    if isinstance(payload, list):
        return _normalize_order_list(payload)
    return []


def save_node_order(path: Path, order: List[str]) -> List[str]:
    cleaned = _normalize_order_list(order)
    atomic_write(Path(path), json.dumps({"order": cleaned}, ensure_ascii=False, indent=2) + "\n")
    return cleaned


class NodeOrderModel(BaseModel):
    order: List[constr(strict=True, min_length=1, max_length=256)] = Field(
        default_factory=list,
        max_length=MAX_ORDER_ITEMS,
    )


def _node_order_view(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    seen_keys = set()
    for node in nodes:
        if not isinstance(node, dict) or not node.get("name"):
            continue
        key = node_sort_key(node)
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)
        items.append({
            "key": key,
            "name": str(node.get("name") or ""),
            "type": str(node.get("type") or ""),
            "server": str(node.get("server") or ""),
            "port": node.get("port") or "",
            "source": node_source_kind(node),
        })
    return items


def create_node_order_router(
    *,
    verify_management: Callable,
    configuration_lock: Callable[[], ContextManager],
    nodes_reader: Callable[[], List[Dict[str, Any]]],
    manual_nodes_reader: Callable[[], List[Dict[str, Any]]],
    template_store: Callable[[], Any],
    order_reader: Callable[[], List[str]],
    order_writer: Callable[[List[str]], List[str]],
) -> APIRouter:
    """Register unified subscription node ordering routes without altering core router contracts."""
    router = APIRouter()

    @router.get("/api/nodes/order", dependencies=[Depends(verify_management)])
    def get_node_order():
        try:
            with configuration_lock():
                saved_order = order_reader()
                items = _node_order_view(nodes_reader())
                return {
                    "items": items,
                    "order": [item["key"] for item in items],
                    "has_custom_order": bool(saved_order),
                }
        except OSError:
            raise HTTPException(
                status_code=503,
                detail={"code": "storage_unavailable", "message": "存储暂不可用，请稍后重试"},
            ) from None

    @router.put("/api/nodes/order", dependencies=[Depends(verify_management)])
    def update_node_order(data: NodeOrderModel):
        try:
            with configuration_lock():
                saved = order_writer(data.order)
                if saved:
                    current_manual = manual_nodes_reader()
                    reordered_manual = sync_manual_nodes_file_order(current_manual, saved)
                    if [strip_internal_proxy_fields(n) for n in reordered_manual] != [
                        strip_internal_proxy_fields(n) for n in current_manual
                    ]:
                        template_store().commit(
                            {
                                "custom_nodes.yaml": yaml.safe_dump(
                                    [strip_internal_proxy_fields(n) for n in reordered_manual],
                                    allow_unicode=True,
                                    sort_keys=False,
                                )
                            },
                            source="node_order",
                        )
                items = _node_order_view(nodes_reader())
                return {
                    "status": "ok",
                    "items": items,
                    "order": [item["key"] for item in items],
                    "has_custom_order": bool(saved),
                }
        except OSError:
            raise HTTPException(
                status_code=503,
                detail={"code": "storage_unavailable", "message": "存储暂不可用，请稍后重试"},
            ) from None

    return router
