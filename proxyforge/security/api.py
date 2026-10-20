"""管理登录、状态、退出及凭据设置 Router；依赖由入口显式注入。"""
from dataclasses import dataclass
from typing import Callable

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel


class ConfigModel(BaseModel):
    SUBSCRIPTION_TOKEN: str

class AdminTokenModel(BaseModel):
    ADMIN_TOKEN: str


@dataclass(frozen=True)
class SecurityApi:
    router: APIRouter
    auth_login: Callable
    auth_status: Callable
    auth_logout: Callable
    get_config: Callable
    update_config: Callable
    update_admin_token: Callable


def create_security_router(*, verify_management, store_reader, limiter_reader, session_writer,
                           cookie_name_reader, subscription_token_reader, subscription_token_writer,
                           admin_minimum_reader, insecure_tokens_reader):
    """只装配六个接口；不创建运行配置、会话、限速器或全局 app。"""
    router = APIRouter()

    @router.post("/api/auth")
    def auth_login(
        request: Request,
        response: Response,
        token: str = Body(..., embed=True),
    ):
        client_key = request.client.host if request.client else "unknown"
        retry_after = limiter_reader().retry_after(client_key)
        if retry_after:
            raise HTTPException(
                status_code=429,
                detail="登录失败次数过多，请稍后重试",
                headers={"Retry-After": str(retry_after)},
            )
        if not store_reader().verify_admin_token(token):
            limiter_reader().record_failure(client_key)
            raise HTTPException(status_code=401, detail="Invalid management credentials")
        limiter_reader().reset(client_key)
        session_writer(response, request)
        return {"status": "ok"}

    @router.get("/api/auth", dependencies=[Depends(verify_management)])
    def auth_status():
        return {"status": "ok"}

    @router.post("/api/logout", dependencies=[Depends(verify_management)])
    def auth_logout(response: Response):
        response.delete_cookie(
            key=cookie_name_reader(),
            path="/",
            httponly=True,
            samesite="strict",
        )
        return {"status": "ok"}

    @router.get("/api/config", dependencies=[Depends(verify_management)])
    def get_config():
        return {
            "SUBSCRIPTION_TOKEN": subscription_token_reader()
        }

    @router.post("/api/config", dependencies=[Depends(verify_management)])
    def update_config(config: ConfigModel):
        new_token = config.SUBSCRIPTION_TOKEN.strip()
        if len(new_token) < 16:
            raise HTTPException(status_code=400, detail="订阅密钥至少需要 16 个字符")
        if new_token in insecure_tokens_reader():
            raise HTTPException(status_code=400, detail="不能使用公开的默认 Token")

        try:
            store_reader().update_subscription_token(new_token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        subscription_token_writer(new_token)

        return {"status": "ok"}

    @router.post("/api/admin-token", dependencies=[Depends(verify_management)])
    def update_admin_token(
        request: Request,
        response: Response,
        config: AdminTokenModel,
    ):
        new_token = config.ADMIN_TOKEN.strip()
        if len(new_token) < admin_minimum_reader():
            raise HTTPException(
                status_code=400,
                detail=f"管理密钥至少需要 {admin_minimum_reader()} 个字符",
            )
        if new_token in insecure_tokens_reader():
            raise HTTPException(status_code=400, detail="不能使用公开的默认管理密钥")

        try:
            store_reader().update_admin_token(new_token)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session_writer(response, request)
        return {"status": "ok"}

    return SecurityApi(router, auth_login, auth_status, auth_logout, get_config,
                       update_config, update_admin_token)
