"""Management inventory routes and separately authenticated Agent routes."""
import json
import os
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, StrictBool, StrictInt, constr

from proxyforge.security.auth_rate_limit import LoginRateLimiter
from proxyforge.control.control_store import CapacityExceeded, InvalidRegistration, UnauthorizedAgent
from proxyforge.control.agent_installation import (
    build_agent_bundle,
    controller_url,
    installation_info,
    render_quick_install_script,
)

ShortText = constr(strict=True, max_length=128)
Identifier = constr(strict=True, pattern=r"^[a-f0-9]{32}$")
Sha256Hex = constr(strict=True, pattern=r"^[a-f0-9]{64}$")
SourceKey = constr(strict=True, pattern=r"^adopt-[a-f0-9]{16}$")
Token = constr(strict=True, min_length=40, max_length=128)


class AgentBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith(("/api/agent/", "/api/agents")):
            return await self.app(scope, receive, send)
        chunks, total = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > 16384:
                return await JSONResponse({"detail": "Agent request exceeds 16 KiB"}, status_code=413)(scope, receive, send)
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                break
        delivered = False
        async def buffered():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
        await self.app(scope, buffered, send)


class Payload(BaseModel):
    class Config:
        extra = "forbid"


class SingboxStatus(Payload):
    installed: StrictBool = False
    running: StrictBool = False
    version: ShortText = ""
    status: constr(strict=True, max_length=32) = "not_installed"


class AdoptServiceItem(Payload):
    core: Literal["sing-box", "xray", "caddy"]
    pid: StrictInt = Field(ge=0)
    service_name: ShortText = ""
    config_path: ShortText
    config_sha256: Sha256Hex


class AdoptEndpointItem(Payload):
    source_key: SourceKey
    core: Literal["sing-box", "xray", "caddy"]
    service_name: ShortText = ""
    config_path: ShortText
    config_sha256: Sha256Hex
    tag: constr(strict=True, max_length=64) = ""
    protocol: constr(strict=True, max_length=32)
    listen: ShortText
    listen_port: StrictInt = Field(ge=1, le=65535)
    tls_mode: Literal["none", "tls", "reality"]
    sni: ShortText = ""
    network: constr(strict=True, max_length=32) = "tcp"
    ws_path: ShortText = ""
    adoptable: StrictBool = True


class AdoptScanOutput(Payload):
    scanned_at: StrictInt = Field(ge=0)
    services: list[AdoptServiceItem] = Field(default_factory=list, max_length=16)
    endpoints: list[AdoptEndpointItem] = Field(default_factory=list, max_length=32)


class AdoptScanUpload(AdoptScanOutput):
    instance_id: Identifier


class AdoptScanTrigger(Payload):
    request_id: Identifier


class AdoptSecretsUpload(Payload):
    instance_id: Identifier
    items: list[dict] = Field(default_factory=list, max_length=32)


class AdoptActionRequest(Payload):
    request_id: Identifier
    custom_name: constr(strict=True, max_length=64) = ""
    server_override: constr(strict=True, max_length=128) = ""
    replace_manual: StrictBool = True


class AdoptIgnoreRequest(Payload):
    ignored: StrictBool = True


class AdoptDisableRequest(Payload):
    request_id: Identifier


class AdoptReturnRequest(Payload):
    request_id: Identifier


class AgentMetadata(Payload):
    instance_id: Identifier
    hostname: ShortText
    machine_id: ShortText = ""
    os: ShortText
    os_version: ShortText
    arch: ShortText
    agent_version: ShortText
    protocol_version: StrictInt = Field(ge=1, le=1000)
    job_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    runtime_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    deployment_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    landing_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    chain_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    gost_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    self_upgrade_protocol_version: StrictInt = Field(default=0, ge=0, le=1000)
    bundle_sha256: ShortText = ""
    nftables_capable: StrictBool | None = None
    uptime: StrictInt = Field(default=0, ge=0)
    addresses: list[ShortText] = Field(default_factory=list, max_length=16)
    supported: StrictBool = False
    singbox: SingboxStatus = Field(default_factory=SingboxStatus)


class Registration(AgentMetadata):
    registration_token: Token


class RegistrationRequest(Payload):
    name: constr(strict=True, min_length=1, max_length=128)


class AgentEdit(RegistrationRequest):
    role: constr(strict=True, pattern=r"^(unassigned|node|landing|both)$") = "unassigned"
    tags: list[constr(strict=True, max_length=32)] = Field(default_factory=list, max_length=16)
    region: constr(strict=True, max_length=32) | None = None
    expire_at: float | int | None = Field(default=None, ge=0)
    quota_bytes: StrictInt | None = Field(default=None, ge=0)
    billing_label: constr(strict=True, max_length=64) | None = None


def attach_agent_routes(
    app,
    management_auth,
    store_provider,
    *,
    manual_nodes_reader=None,
    replace_manual_node=None,
    rename_template_references=None,
):
    admin = APIRouter(prefix="/api/agents", dependencies=[Depends(management_auth)])
    agent = APIRouter(prefix="/api/agent")
    # A bounded, shared unauthenticated enrollment limiter avoids trusting
    # forwarding headers and avoids growing a dictionary per attacker IP.
    limiter = LoginRateLimiter(max_failures=20, window_seconds=60, block_seconds=60)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        if request.url.path.startswith(("/api/agent/", "/api/agents")):
            return JSONResponse({"detail": "Invalid Agent request schema"}, status_code=422)
        return await request_validation_exception_handler(request, exc)

    @app.exception_handler(UnauthorizedAgent)
    async def unauthorized(request, exc):
        return JSONResponse({"detail": "Invalid Agent credentials"}, status_code=401)

    @app.exception_handler(InvalidRegistration)
    async def invalid_registration(request, exc):
        return JSONResponse({"detail": "Registration expired or already used; issue a new token"}, status_code=401)

    @app.exception_handler(CapacityExceeded)
    async def capacity_error(request, exc):
        return JSONResponse({"detail": "Control plane capacity reached"}, status_code=429)

    @app.exception_handler(sqlite3.Error)
    async def database_error(request, exc):
        return JSONResponse({"detail": "Control database unavailable"}, status_code=503)

    def observed_ip(request):
        return request.client.host if request.client else ""

    @admin.post("/registration-tokens")
    def issue_token(data: RegistrationRequest):
        return store_provider().issue_registration(data.name)

    def _latest_bundle_sha256():
        try:
            _, digest = build_agent_bundle()
            return digest
        except Exception:
            return ""

    @admin.get("")
    def list_agents():
        return {"agents": store_provider().list_agents(), "latest_bundle_sha256": _latest_bundle_sha256()}

    @admin.get("/install-command")
    def install_command():
        # Only deployment configuration is trusted, never Host/forwarding headers.
        return JSONResponse(installation_info(os.environ.get("PROXYFORGE_PUBLIC_URL", "")),
                            headers={"Cache-Control": "no-store"})

    @admin.get("/{agent_id}")
    def get_agent(agent_id: str):
        try:
            return store_provider().get_agent(agent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")

    @admin.patch("/{agent_id}")
    def edit_agent(agent_id: str, data: AgentEdit):
        from proxyforge.control.control_store import _UNSET
        fields = data.model_fields_set
        try:
            return store_provider().update_agent(
                agent_id,
                data.name,
                data.role,
                data.tags,
                region=data.region if "region" in fields else _UNSET,
                expire_at=data.expire_at if "expire_at" in fields else _UNSET,
                quota_bytes=data.quota_bytes if "quota_bytes" in fields else _UNSET,
                billing_label=data.billing_label if "billing_label" in fields else _UNSET,
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")

    @admin.post("/{agent_id}/revoke")
    def revoke_agent(agent_id: str):
        try:
            store_provider().revoke(agent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")
        return {"status": "ok"}

    @admin.delete("/{agent_id}")
    def remove_agent(agent_id: str):
        try:
            store_provider().revoke(agent_id, remove=True)
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")
        return Response(status_code=204)

    @agent.get("/package.tar.gz")
    def get_agent_package():
        payload, digest = build_agent_bundle()
        return Response(
            content=payload,
            media_type="application/gzip",
            headers={"ETag": f'"{digest}"', "Cache-Control": "public, max-age=60"},
        )

    @agent.get("/install.sh")
    def get_quick_install_script():
        _, digest = build_agent_bundle()
        raw_public = os.environ.get("PROXYFORGE_PUBLIC_URL", "")
        default_server = ""
        try:
            if raw_public:
                default_server = controller_url(raw_public)
        except ValueError:
            default_server = ""
        script = render_quick_install_script(default_server=default_server, bundle_sha256=digest)
        return Response(
            content=script,
            media_type="text/x-shellscript; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    @agent.post("/register")
    def register_agent(data: Registration, request: Request):
        retry = limiter.retry_after("registration")
        if retry:
            raise HTTPException(status_code=429, detail="Retry later", headers={"Retry-After": str(retry)})
        try:
            # model dump excludes the only secret before persistence.
            metadata = json.loads(data.model_dump_json(exclude={"registration_token"}))
            return store_provider().register(data.registration_token, metadata, observed_ip(request))
        except InvalidRegistration:
            limiter.record_failure("registration")
            raise

    @agent.post("/heartbeat")
    def heartbeat(data: AgentMetadata, request: Request, authorization: str = Header(default="")):
        if not authorization.startswith("Bearer ") or len(authorization) > 160:
            raise UnauthorizedAgent()
        res = store_provider().heartbeat(authorization[7:], json.loads(data.model_dump_json()), observed_ip(request))
        digest = _latest_bundle_sha256()
        if digest:
            res["latest_bundle_sha256"] = digest
        return res

    @agent.post("/adoptions")
    def upload_adoptions(data: AdoptScanUpload, authorization: str = Header(default="")):
        if not authorization.startswith("Bearer ") or len(authorization) > 160:
            raise UnauthorizedAgent()
        scan_payload = json.loads(data.model_dump_json(exclude={"instance_id"}))
        return store_provider().record_adoption_scan(authorization[7:], data.instance_id, scan_payload)

    @agent.post("/adoptions/secrets")
    def upload_adoption_secrets(data: AdoptSecretsUpload, authorization: str = Header(default="")):
        if not authorization.startswith("Bearer ") or len(authorization) > 160:
            raise UnauthorizedAgent()
        try:
            return store_provider().record_adoption_secrets(authorization[7:], data.instance_id, data.items)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid adoption secrets payload") from None

    @admin.get("/{agent_id}/adoptions")
    def get_adoptions(agent_id: str):
        store = store_provider()
        try:
            store.get_agent(agent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")
        manual_nodes = manual_nodes_reader() if callable(manual_nodes_reader) else None
        return {"adoptions": store.list_adopted_nodes(agent_id, manual_nodes=manual_nodes)}

    @admin.post("/{agent_id}/adoptions/{source_key}/adopt")
    def adopt_endpoint(agent_id: str, source_key: str, data: AdoptActionRequest):
        store = store_provider()
        matched_manual_name = ""
        if data.replace_manual and callable(manual_nodes_reader):
            manual_nodes = manual_nodes_reader()
            items = store.list_adopted_nodes(agent_id, manual_nodes=manual_nodes)
            matched = next((ep for ep in items if ep["source_key"] == source_key), None)
            if matched and matched.get("matched_manual_name"):
                matched_manual_name = matched["matched_manual_name"]
        effective_name = data.custom_name or matched_manual_name
        if data.replace_manual and matched_manual_name:
            effective_name = matched_manual_name
        try:
            result = store.adopt_endpoint(
                agent_id,
                source_key,
                data.request_id,
                custom_name=effective_name,
                server_override=data.server_override,
            )
        except ValueError:
            raise HTTPException(status_code=422, detail="Cannot adopt endpoint without valid extracted credentials") from None
        if data.replace_manual and matched_manual_name and callable(replace_manual_node):
            adopted_display = (result or {}).get("adopted_display_name", "")
            if adopted_display:
                try:
                    rep = replace_manual_node(matched_manual_name, adopted_display)
                    if isinstance(result, dict):
                        result["manual_replacement"] = rep
                except Exception:
                    pass
        return result

    @admin.post("/{agent_id}/adoptions/{source_key}/ignore")
    def ignore_adopted_endpoint(agent_id: str, source_key: str, data: AdoptIgnoreRequest):
        try:
            return store_provider().set_adoption_ignored(agent_id, source_key, ignored=data.ignored)
        except ValueError:
            raise HTTPException(status_code=422, detail="Cannot change ignore status for this endpoint") from None

    @admin.post("/{agent_id}/adoptions/{source_key}/disable")
    def disable_adopted_endpoint(agent_id: str, source_key: str, data: AdoptDisableRequest):
        try:
            return store_provider().disable_adopted_endpoint(agent_id, source_key, data.request_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Cannot disable host service for this endpoint") from None

    @admin.post("/{agent_id}/adoptions/{source_key}/return")
    def return_adopted_endpoint(agent_id: str, source_key: str, data: AdoptReturnRequest):
        try:
            return store_provider().return_adopted_endpoint(agent_id, source_key, data.request_id)
        except ValueError:
            raise HTTPException(status_code=422, detail="Cannot return adopted endpoint") from None

    @admin.post("/{agent_id}/adopt-scan")
    def trigger_adopt_scan(agent_id: str, data: AdoptScanTrigger):
        return store_provider().create_job(agent_id, data.request_id, "adopt_scan", {})

    from proxyforge.control.job_api import attach_job_routes
    attach_job_routes(app, admin, agent, store_provider)
    from proxyforge.control.deployment_api import attach_deployment_routes
    attach_deployment_routes(
        app,
        admin,
        store_provider,
        rename_template_references=rename_template_references,
    )
    from proxyforge.control.gost_api import attach_gost_routes
    attach_gost_routes(admin, agent, store_provider)
    app.add_middleware(AgentBodyLimit)
    app.include_router(admin)
    app.include_router(agent)
