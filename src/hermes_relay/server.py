"""ASGI application: OAuth + Streamable-HTTP MCP."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from hermes_relay import __version__
from hermes_relay.agent import HermesRunner
from hermes_relay.config import Settings
from hermes_relay.gateway import build_mcp_server
from hermes_relay.jobs import JobStore
from hermes_relay.limits import SlidingWindowLimiter
from hermes_relay.oauth import (
    OAuthError,
    OAuthService,
    handle_approve,
    handle_authorize,
    handle_register,
    handle_revoke,
    handle_token,
    json_error,
)
from hermes_relay.security import (
    BodyLimitMiddleware,
    HostOriginMiddleware,
    SecurityHeadersMiddleware,
    client_ip,
    html_response,
)

logger = logging.getLogger("hermes_relay.server")


@dataclass
class RelayState:
    settings: Settings
    jobs: JobStore
    oauth: OAuthService
    limiter: SlidingWindowLimiter


def create_app(settings: Settings, *, require_auth: bool = True) -> Starlette:
    runner = HermesRunner(settings)
    jobs = JobStore(settings, runner)
    oauth = OAuthService(settings)
    limiter = SlidingWindowLimiter()
    state = RelayState(settings=settings, jobs=jobs, oauth=oauth, limiter=limiter)
    mcp_server = build_mcp_server(jobs)
    mcp_app = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host=settings.bind_host,
        max_request_body_size=settings.max_request_body_bytes,
    )

    async def landing(_request: Request) -> Response:
        return html_response(_landing_html(settings))

    async def healthz(_request: Request) -> Response:
        return JSONResponse(
            {
                "ok": True,
                "gateway": "hermes-relay",
                "version": __version__,
                "mcp": "/mcp",
            }
        )

    async def as_metadata(_request: Request) -> Response:
        return JSONResponse(oauth.metadata())

    async def pr_metadata(_request: Request) -> Response:
        return JSONResponse(oauth.protected_resource_metadata())

    async def authorize(request: Request) -> Response:
        return await handle_authorize(request, oauth)

    async def approve(request: Request) -> Response:
        return await handle_approve(request, oauth)

    async def register(request: Request) -> Response:
        return await handle_register(request, oauth)

    async def token(request: Request) -> Response:
        return await handle_token(request, oauth)

    async def revoke(request: Request) -> Response:
        return await handle_revoke(request, oauth)

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        await jobs.start()
        async with mcp_app.router.lifespan_context(mcp_app):
            try:
                yield
            finally:
                await jobs.shutdown()

    routes = [
        Route("/", landing, methods=["GET"]),
        Route("/healthz", healthz, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", as_metadata, methods=["GET"]),
        Route("/.well-known/openid-configuration", as_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource", pr_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", pr_metadata, methods=["GET"]),
        Route("/oauth/authorize", authorize, methods=["GET"]),
        Route("/oauth/approve", approve, methods=["GET", "POST"]),
        Route("/oauth/register", register, methods=["POST"]),
        Route("/oauth/token", token, methods=["POST"]),
        Route("/oauth/revoke", revoke, methods=["POST"]),
        Mount("/", mcp_app),
    ]

    middleware = [
        Middleware(SecurityHeadersMiddleware),
        Middleware(
            HostOriginMiddleware,
            allowed_hosts=settings.allowed_hosts(),
            allowed_origins=settings.allowed_origins(),
        ),
        Middleware(BodyLimitMiddleware, max_bytes=settings.max_request_body_bytes),
        Middleware(
            RateLimitMiddleware,
            limiter=limiter,
            mcp_limit=settings.rate_limit_mcp_per_minute,
            oauth_limit=settings.rate_limit_oauth_per_minute,
        ),
        Middleware(CorsMiddleware, origin=settings.public_origin),
        Middleware(McpAuthMiddleware, oauth=oauth, enabled=require_auth),
    ]

    app = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
    app.state.relay = state
    return app


class McpAuthMiddleware:
    def __init__(self, app: ASGIApp, oauth: OAuthService, enabled: bool = True) -> None:
        self.app = app
        self.oauth = oauth
        self.enabled = enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return
        from starlette.datastructures import Headers

        headers = Headers(scope=scope)
        authorization = headers.get("authorization") or ""
        if not authorization.lower().startswith("bearer "):
            await _unauthorized(scope, receive, send, self.oauth)
            return
        token = authorization[7:].strip()
        try:
            self.oauth.verify_token(token)
        except OAuthError as exc:
            response = json_error(exc)
            response.headers["WWW-Authenticate"] = self.oauth.www_authenticate()
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        limiter: SlidingWindowLimiter,
        mcp_limit: int,
        oauth_limit: int,
    ) -> None:
        self.app = app
        self.limiter = limiter
        self.mcp_limit = mcp_limit
        self.oauth_limit = oauth_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path") or ""
        ip = client_ip(scope)
        if path.startswith("/mcp"):
            decision = self.limiter.check(f"mcp:{ip}", self.mcp_limit)
        elif path.startswith("/oauth/"):
            decision = self.limiter.check(f"oauth:{ip}", self.oauth_limit)
        else:
            decision = self.limiter.check(f"other:{ip}", max(self.oauth_limit, 120))
        if not decision.allowed:
            response = JSONResponse(
                {"error": "rate_limited"},
                status_code=429,
                headers={"Retry-After": str(int(decision.retry_after_seconds) + 1)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class CorsMiddleware:
    def __init__(self, app: ASGIApp, origin: str) -> None:
        self.app = app
        self.origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if scope.get("method") == "OPTIONS":
            response = Response(status_code=204, headers=self._headers())
            await response(scope, receive, send)
            return

        async def send_wrapped(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                for key, value in self._headers().items():
                    headers.append((key.encode("latin-1"), value.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapped)

    def _headers(self) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": self.origin or "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Accept",
            "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
            "Access-Control-Max-Age": "600",
        }


async def _unauthorized(scope: Scope, receive: Receive, send: Send, oauth: OAuthService) -> None:
    response = JSONResponse(
        {"error": "invalid_token", "error_description": "authentication required"},
        status_code=401,
        headers={"WWW-Authenticate": oauth.www_authenticate()},
    )
    await response(scope, receive, send)


def _landing_html(settings: Settings) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>hermes-relay</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: #101218; color: #e8e6e3;
    }}
    main {{ max-width: 44rem; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }}
    h1 {{ font-size: 1.8rem; margin-bottom: 0.35rem; }}
    .muted {{ color: #a9a59c; }}
    code, pre {{
      background: #1a1d27; border: 1px solid #2d3140; border-radius: 8px;
    }}
    code {{ padding: 0.1rem 0.35rem; }}
    pre {{ padding: 0.9rem 1rem; overflow: auto; }}
    a {{ color: #e3b341; }}
    ul {{ line-height: 1.6; }}
    .card {{
      margin-top: 1.5rem; padding: 1.1rem 1.2rem;
      border: 1px solid #2d3140; border-radius: 12px; background: #171a24;
    }}
  </style>
</head>
<body>
  <main>
    <h1>hermes-relay</h1>
    <p class="muted">v{__version__} · Streamable-HTTP MCP gateway · Grok Bot → local Hermes</p>
    <div class="card">
      <p>This process is bound to loopback. TLS and the public hostname terminate at your tunnel or reverse proxy.</p>
      <ul>
        <li>MCP endpoint: <code>/mcp</code> (OAuth bearer required)</li>
        <li>Health: <a href="/healthz"><code>/healthz</code></a></li>
        <li>Authorization server: <a href="/.well-known/oauth-authorization-server"><code>/.well-known/oauth-authorization-server</code></a></li>
        <li>Protected resource: <a href="/.well-known/oauth-protected-resource"><code>/.well-known/oauth-protected-resource</code></a></li>
      </ul>
      <p>In Grok Bot, add a <strong>custom MCP connector</strong> pointing at your public <code>https://…/mcp</code> URL. Use OAuth — do not paste an Authorization header or the owner secret.</p>
      <p class="muted">Direction notice: this enables Grok Bot to call Hermes. Hermes cannot call Grok Bot built-ins.</p>
    </div>
  </main>
</body>
</html>"""
