"""Persistent credentials and signed management sessions for ProxyForge."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Optional, Union


CONFIG_SCHEMA_VERSION = 2
INSECURE_DEFAULT_TOKENS = {"", "my_secret_token"}
ADMIN_TOKEN_MIN_LENGTH = 16
PBKDF2_ITERATIONS = 210_000


class RuntimeConfigError(RuntimeError):
    """Raised when persisted security configuration cannot be trusted."""


def _set_private_permissions(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows and some mounted filesystems do not implement POSIX modes.
        pass


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        with temporary_path.open("w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        _set_private_permissions(temporary_path)
        os.replace(temporary_path, path)
        _set_private_permissions(path)
    finally:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass


def hash_admin_token(token: str, salt_hex: Optional[str] = None) -> tuple:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        token.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return salt.hex(), digest.hex()


def verify_admin_token(token: str, salt_hex: str, expected_hash: str) -> bool:
    try:
        _, actual_hash = hash_admin_token(token, salt_hex)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def create_session_token(
    session_secret: str,
    ttl_seconds: int,
    now: Optional[int] = None,
) -> str:
    issued_at = int(time.time() if now is None else now)
    expires_at = issued_at + ttl_seconds
    nonce = secrets.token_urlsafe(18)
    payload = f"v1.{expires_at}.{nonce}"
    signature = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{signature}"


def verify_session_token(
    token: str,
    session_secret: str,
    ttl_seconds: int,
    now: Optional[int] = None,
) -> bool:
    try:
        version, expires_text, nonce, supplied_signature = token.split(".", 3)
        expires_at = int(expires_text)
    except (AttributeError, TypeError, ValueError):
        return False
    if version != "v1" or not nonce:
        return False

    current_time = int(time.time() if now is None else now)
    if expires_at < current_time or expires_at > current_time + ttl_seconds + 60:
        return False

    payload = f"{version}.{expires_at}.{nonce}"
    expected_signature = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(supplied_signature, expected_signature)


class RuntimeConfigStore:
    def __init__(
        self,
        config_path: Union[str, Path],
        bootstrap_path: Union[str, Path],
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        # Resolve once at construction so later cwd changes (tests, service
        # wrappers, reloaders) can never redirect credential writes elsewhere.
        self.config_path = Path(config_path).resolve()
        self.bootstrap_path = Path(bootstrap_path).resolve()
        self.environ = os.environ if environ is None else environ
        self._config: dict[str, Any] | None = None
        self._lock = threading.RLock()

    @property
    def config(self) -> dict[str, Any]:
        if self._config is None:
            raise RuntimeConfigError("运行配置尚未加载")
        return dict(self._config)

    @property
    def subscription_token(self) -> str:
        return str(self.config["subscription_token"])

    def load_or_create(self) -> dict[str, Any]:
        with self._lock:
            if self.config_path.exists():
                try:
                    if not self.config_path.is_file():
                        raise ValueError("运行配置路径不是普通文件")
                    stored = json.loads(self.config_path.read_text(encoding="utf-8"))
                    if not isinstance(stored, dict):
                        raise ValueError("运行配置根节点必须是对象")
                except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeConfigError(
                        f"无法读取 {self.config_path}，请恢复备份或修复该文件"
                    ) from exc

                if stored.get("schema_version") == CONFIG_SCHEMA_VERSION:
                    config = self._validate_v2(stored)
                    if verify_admin_token(
                        config["subscription_token"],
                        config["admin_token_salt"],
                        config["admin_token_hash"],
                    ):
                        raise RuntimeConfigError("管理密钥不能与订阅密钥相同")
                    for insecure_token in INSECURE_DEFAULT_TOKENS:
                        if verify_admin_token(
                            insecure_token,
                            config["admin_token_salt"],
                            config["admin_token_hash"],
                        ):
                            raise RuntimeConfigError("持久化配置包含不安全的管理密钥")
                    if config["subscription_token"] in INSECURE_DEFAULT_TOKENS:
                        config["subscription_token"] = secrets.token_urlsafe(32)
                        self._persist(config)
                    self._config = config
                    return self.config

                if "secret_token" not in stored:
                    raise RuntimeConfigError("未知的运行配置版本，拒绝不安全降级")
                subscription_token = str(stored.get("secret_token", "")).strip()
                if subscription_token in INSECURE_DEFAULT_TOKENS:
                    subscription_token = secrets.token_urlsafe(32)
                config = self._new_v2_config(subscription_token)
                self._persist(config)
                self._config = config
                return self.config

            subscription_token = str(self.environ.get("SECRET_TOKEN", "")).strip()
            if subscription_token in INSECURE_DEFAULT_TOKENS:
                subscription_token = secrets.token_urlsafe(32)
            config = self._new_v2_config(subscription_token)
            self._persist(config)
            self._config = config
            return self.config

    def _new_v2_config(self, subscription_token: str) -> dict[str, Any]:
        admin_token = str(self.environ.get("ADMIN_TOKEN", "")).strip()
        generated_admin_token = False
        if not admin_token:
            admin_token = secrets.token_urlsafe(32)
            generated_admin_token = True
        elif admin_token in INSECURE_DEFAULT_TOKENS or len(admin_token) < ADMIN_TOKEN_MIN_LENGTH:
            raise RuntimeConfigError(
                f"ADMIN_TOKEN 至少需要 {ADMIN_TOKEN_MIN_LENGTH} 个字符且不能使用公开默认值"
            )
        if hmac.compare_digest(admin_token, subscription_token):
            raise RuntimeConfigError("ADMIN_TOKEN 不能与订阅密钥相同")

        salt, token_hash = hash_admin_token(admin_token)
        if generated_admin_token:
            _atomic_write(self.bootstrap_path, admin_token + "\n")

        return {
            "schema_version": CONFIG_SCHEMA_VERSION,
            "subscription_token": subscription_token,
            "admin_token_salt": salt,
            "admin_token_hash": token_hash,
            "session_secret": secrets.token_urlsafe(48),
        }

    @staticmethod
    def _validate_v2(config: Mapping[str, Any]) -> dict[str, Any]:
        required = (
            "subscription_token",
            "admin_token_salt",
            "admin_token_hash",
            "session_secret",
        )
        normalized = dict(config)
        for key in required:
            value = normalized.get(key)
            if not isinstance(value, str) or not value.strip():
                raise RuntimeConfigError(f"持久化配置缺少有效字段: {key}")
            normalized[key] = value.strip()
        normalized["schema_version"] = CONFIG_SCHEMA_VERSION
        return normalized

    def _persist(self, config: Mapping[str, Any]) -> None:
        content = json.dumps(dict(config), ensure_ascii=False, indent=2) + "\n"
        _atomic_write(self.config_path, content)

    def verify_admin_token(self, token: str) -> bool:
        config = self.config
        return verify_admin_token(
            token,
            config["admin_token_salt"],
            config["admin_token_hash"],
        )

    def verify_session(self, token: str, ttl_seconds: int) -> bool:
        return verify_session_token(
            token,
            self.config["session_secret"],
            ttl_seconds,
        )

    def create_session(self, ttl_seconds: int) -> str:
        return create_session_token(self.config["session_secret"], ttl_seconds)

    def update_subscription_token(self, token: str) -> None:
        with self._lock:
            if self.verify_admin_token(token):
                raise ValueError("订阅密钥不能与管理密钥相同")
            config = self.config
            config["subscription_token"] = token
            self._persist(config)
            self._config = config

    def update_admin_token(self, token: str) -> None:
        if token in INSECURE_DEFAULT_TOKENS or len(token) < ADMIN_TOKEN_MIN_LENGTH:
            raise ValueError(f"管理密钥至少需要 {ADMIN_TOKEN_MIN_LENGTH} 个字符")
        with self._lock:
            config = self.config
            if hmac.compare_digest(token, config["subscription_token"]):
                raise ValueError("管理密钥不能与订阅密钥相同")
            salt, token_hash = hash_admin_token(token)
            config["admin_token_salt"] = salt
            config["admin_token_hash"] = token_hash
            config["session_secret"] = secrets.token_urlsafe(48)
            self._persist(config)
            self._config = config
            try:
                self.bootstrap_path.unlink(missing_ok=True)
            except OSError:
                pass
