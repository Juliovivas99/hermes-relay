"""Host checks, redaction, structured logging, and error sanitization."""

from __future__ import annotations

import json
import logging
import re
import secrets
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from hermes_relay.config import is_loopback_host

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[PX^_][\s\S]*?\x1b\\")
_ABS_PATH_RE = re.compile(
    r"(?P<path>(?:/home/|/Users/|/root/|/opt/|/var/|/private/|/tmp/)[^\s'\"`]+|[A-Za-z]:\\[^\s'\"`]+)"
)
_SECRETISH_RE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._\-~+/=]+|"
    r"sk-[A-Za-z0-9]{10,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"(?:api[_-]?key|token|secret|password|authorization)[=:\s]+[^\s'\"&,]+)"
)
_REDACT_KEYS = re.compile(
    r"(?i)(secret|token|password|authorization|api[_-]?key|cookie|set-cookie|refresh|owner)"
)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def sanitize_text(text: str) -> str:
    """Remove ANSI, absolute paths, and secret-looking tokens from operator-facing text."""
    cleaned = strip_ansi(text)
    cleaned = _ABS_PATH_RE.sub("<path>", cleaned)
    cleaned = _SECRETISH_RE.sub("<redacted>", cleaned)
    return cleaned


def bound_text(text: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0:
        return "", True
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if _REDACT_KEYS.search(str(key)):
            redacted[key] = "<redacted>"
        elif isinstance(value, Mapping):
            redacted[key] = redact_mapping(value)
        elif isinstance(value, str):
            redacted[key] = sanitize_text(value)
        else:
            redacted[key] = value
    return redacted


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_text(record.getMessage()),
        }
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k
            not in {
                "args",
                "created",
                "exc_info",
                "exc_text",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "msg",
                "name",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "stack_info",
                "thread",
                "threadName",
                "taskName",
            }
        }
        if extras:
            payload["data"] = redact_mapping(extras)
        if record.exc_info:
            payload["exc"] = sanitize_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingJsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def host_allowed(host: str | None, allowed: list[str]) -> bool:
    if not host:
        return False
    if host in allowed:
        return True
    hostname = host.split("]")[-1]
    if hostname.startswith(":"):
        # [::1]:port already handled by exact/wildcard entries
        pass
    bare = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    for pattern in allowed:
        if pattern.endswith(":*"):
            base = pattern[:-2]
            if host == base or host.startswith(base + ":"):
                return True
        if pattern == bare:
            return True
    return False


def origin_allowed(origin: str | None, allowed: list[str]) -> bool:
    if not origin:
        return True
    if origin in allowed:
        return True
    parsed = urlparse(origin)
    origin_base = f"{parsed.scheme}://{parsed.hostname}" if parsed.hostname else origin
    for pattern in allowed:
        if pattern.endswith(":*"):
            base = pattern[:-2]
            if origin == base or origin.startswith(base + ":"):
                return True
            if origin_base == base:
                return True
        if pattern == origin_base:
            return True
    return False


class HostOriginMiddleware:
    """Reject unexpected Host/Origin headers (DNS-rebinding protection)."""

    def __init__(self, app: ASGIApp, allowed_hosts: list[str], allowed_origins: list[str]) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.allowed_origins = allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        host = headers.get("host")
        origin = headers.get("origin")
        if not host_allowed(host, self.allowed_hosts):
            response = JSONResponse({"error": "invalid_host"}, status_code=400)
            await response(scope, receive, send)
            return
        if not origin_allowed(origin, self.allowed_origins):
            response = JSONResponse({"error": "invalid_origin"}, status_code=400)
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        length = headers.get("content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    response = JSONResponse({"error": "payload_too_large"}, status_code=413)
                    await response(scope, receive, send)
                    return
            except ValueError:
                response = JSONResponse({"error": "invalid_content_length"}, status_code=400)
                await response(scope, receive, send)
                return

        seen = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                seen += len(body)
                if seen > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            response = JSONResponse({"error": "payload_too_large"}, status_code=413)
            await response(scope, receive, send)


class _BodyTooLarge(Exception):
    pass


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapped(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                extra = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"cache-control": b"no-store",
                    b"x-dns-prefetch-control": b"off",
                }
                present = {k.lower() for k, _ in headers}
                for key, value in extra.items():
                    if key not in present:
                        headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapped)


def constant_time_equals(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def client_ip(scope: Scope) -> str:
    headers = Headers(scope=scope)
    # Do not trust X-Forwarded-For by default; bind is loopback and TLS is external.
    forwarded = headers.get("x-real-ip")
    if forwarded and is_loopback_host(str(scope.get("client", ["127.0.0.1"])[0])):
        return forwarded.split(",")[0].strip()
    client = scope.get("client")
    if client:
        return str(client[0])
    return "unknown"


def html_response(content: str, status_code: int = 200) -> Response:
    return Response(
        content,
        status_code=status_code,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        },
    )
