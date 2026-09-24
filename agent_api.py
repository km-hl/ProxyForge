"""Management inventory routes and separately authenticated Agent routes."""
import json
import sqlite3

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, StrictBool, StrictInt, constr

from auth_rate_limit import LoginRateLimiter
from control_store import CapacityExceeded, InvalidRegistration, UnauthorizedAgent

ShortText = constr(strict=True, max_length=128)
Identifier = constr(strict=True, pattern=r"^[a-f0-9]{32}$")
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


def attach_agent_routes(app, management_auth, store_provider):
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

    @admin.get("")
    def list_agents():
        return {"agents": store_provider().list_agents()}

    @admin.get("/{agent_id}")
    def get_agent(agent_id: str):
        try:
            return store_provider().get_agent(agent_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Agent not found")

    @admin.patch("/{agent_id}")
    def edit_agent(agent_id: str, data: AgentEdit):
        try:
            return store_provider().update_agent(agent_id, data.name, data.role, data.tags)
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
        return store_provider().heartbeat(authorization[7:], json.loads(data.model_dump_json()), observed_ip(request))

    from job_api import attach_job_routes
    attach_job_routes(app, admin, agent, store_provider)
    app.add_middleware(AgentBodyLimit)
    app.include_router(admin)
    app.include_router(agent)
