"""Single-owner OAuth 2.1 provider (authorization code + PKCE + DCR)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from hermes_relay.config import Settings
from hermes_relay.security import constant_time_equals, html_response, new_token, sanitize_text

logger = logging.getLogger("hermes_relay.oauth")

SCOPE = "mcp"
ALG = "HS256"


class OAuthError(Exception):
    def __init__(self, error: str, description: str, status_code: int = 400) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status_code = status_code


@dataclass
class RegisteredClient:
    client_id: str
    client_name: str
    redirect_uris: list[str]
    token_endpoint_auth_method: str
    created_at: float = field(default_factory=time.time)


@dataclass
class PendingAuthorization:
    request_id: str
    client_id: str
    redirect_uri: str
    state: str | None
    code_challenge: str
    resource: str
    created_at: float = field(default_factory=time.time)
    csrf: str = field(default_factory=lambda: new_token(16))


@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    resource: str
    created_at: float = field(default_factory=time.time)
    used: bool = False


@dataclass
class AccessClaims:
    subject: str
    client_id: str
    scope: str
    resource: str
    jti: str
    token_type: str


class OAuthService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.clients: dict[str, RegisteredClient] = {}
        self.pending: dict[str, PendingAuthorization] = {}
        self.codes: dict[str, AuthCode] = {}
        self.denylist: dict[str, float] = {}
        self._max_clients = 64

    def _purge(self) -> None:
        now = time.time()
        expired_pending = [
            k
            for k, v in self.pending.items()
            if now - v.created_at > self.settings.auth_code_ttl_seconds
        ]
        for key in expired_pending:
            self.pending.pop(key, None)
        expired_codes = [
            k
            for k, v in self.codes.items()
            if now - v.created_at > self.settings.auth_code_ttl_seconds or v.used
        ]
        for key in expired_codes:
            self.codes.pop(key, None)
        expired_deny = [k for k, exp in self.denylist.items() if exp <= now]
        for key in expired_deny:
            self.denylist.pop(key, None)

    def metadata(self) -> dict[str, Any]:
        issuer = self.settings.issuer
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register",
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "resource_indicators_supported": True,
        }

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.settings.resource,
            "authorization_servers": [self.settings.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
        }

    def register_client(self, body: dict[str, Any]) -> dict[str, Any]:
        self._purge()
        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            raise OAuthError("invalid_client_metadata", "redirect_uris is required")
        clean_uris: list[str] = []
        for uri in redirect_uris:
            if not isinstance(uri, str) or not _valid_redirect(uri):
                raise OAuthError("invalid_redirect_uri", "redirect_uri is not allowed")
            clean_uris.append(uri)
        if len(self.clients) >= self._max_clients:
            oldest = min(self.clients.values(), key=lambda c: c.created_at)
            self.clients.pop(oldest.client_id, None)
        client = RegisteredClient(
            client_id=new_token(18),
            client_name=_safe_name(body.get("client_name")),
            redirect_uris=clean_uris,
            token_endpoint_auth_method="none",
        )
        self.clients[client.client_id] = client
        logger.info("oauth client registered", extra={"client_id": client.client_id})
        return {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "client_id_issued_at": int(client.created_at),
        }

    def begin_authorization(self, params: dict[str, str]) -> PendingAuthorization:
        self._purge()
        if params.get("response_type") != "code":
            raise OAuthError("unsupported_response_type", "only response_type=code is supported")
        client_id = params.get("client_id") or ""
        client = self.clients.get(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id")
        redirect_uri = params.get("redirect_uri") or ""
        if redirect_uri not in client.redirect_uris:
            raise OAuthError("invalid_request", "redirect_uri does not match registration")
        if params.get("code_challenge_method") != "S256":
            raise OAuthError("invalid_request", "code_challenge_method must be S256")
        challenge = params.get("code_challenge") or ""
        if len(challenge) < 43 or len(challenge) > 128:
            raise OAuthError("invalid_request", "code_challenge is invalid")
        resource = params.get("resource") or self.settings.resource
        if resource != self.settings.resource:
            raise OAuthError("invalid_target", "resource does not match this gateway")
        pending = PendingAuthorization(
            request_id=new_token(16),
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=params.get("state"),
            code_challenge=challenge,
            resource=resource,
        )
        self.pending[pending.request_id] = pending
        return pending

    def approve(self, request_id: str, owner_secret: str, *, allow: bool) -> str:
        pending = self.pending.pop(request_id, None)
        if pending is None:
            raise OAuthError("invalid_request", "authorization request expired")
        if not constant_time_equals(owner_secret, self.settings.owner_secret):
            # Put it back so a typo does not burn the request, but delay attackers.
            self.pending[request_id] = pending
            raise OAuthError("access_denied", "owner approval failed", status_code=403)
        query: dict[str, str] = {}
        if pending.state:
            query["state"] = pending.state
        if not allow:
            query["error"] = "access_denied"
            return _redirect(pending.redirect_uri, query)
        code = new_token(24)
        self.codes[code] = AuthCode(
            code=code,
            client_id=pending.client_id,
            redirect_uri=pending.redirect_uri,
            code_challenge=pending.code_challenge,
            resource=pending.resource,
        )
        query["code"] = code
        logger.info("oauth authorization approved", extra={"client_id": pending.client_id})
        return _redirect(pending.redirect_uri, query)

    def exchange(self, form: dict[str, str]) -> dict[str, Any]:
        self._purge()
        grant = form.get("grant_type")
        if grant == "authorization_code":
            return self._exchange_code(form)
        if grant == "refresh_token":
            return self._refresh(form)
        raise OAuthError("unsupported_grant_type", "unsupported grant_type")

    def _exchange_code(self, form: dict[str, str]) -> dict[str, Any]:
        code = form.get("code") or ""
        record = self.codes.get(code)
        if record is None or record.used:
            raise OAuthError("invalid_grant", "authorization code is invalid")
        if form.get("client_id") != record.client_id:
            raise OAuthError("invalid_client", "client_id mismatch")
        if form.get("redirect_uri") != record.redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri mismatch")
        verifier = form.get("code_verifier") or ""
        if not _pkce_ok(verifier, record.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        resource = form.get("resource") or record.resource
        if resource != record.resource:
            raise OAuthError("invalid_target", "resource does not match this gateway")
        record.used = True
        return self._issue_tokens(record.client_id, record.resource)

    def _refresh(self, form: dict[str, str]) -> dict[str, Any]:
        token = form.get("refresh_token") or ""
        claims = self.verify_token(token, expected_type="refresh")
        if form.get("client_id") and form["client_id"] != claims.client_id:
            raise OAuthError("invalid_client", "client_id mismatch")
        self.revoke_jti(claims.jti, self.settings.refresh_token_ttl_seconds)
        return self._issue_tokens(claims.client_id, claims.resource)

    def _issue_tokens(self, client_id: str, resource: str) -> dict[str, Any]:
        now = int(time.time())
        access_jti = new_token(12)
        refresh_jti = new_token(12)
        access = jwt.encode(
            {
                "iss": self.settings.issuer,
                "aud": resource,
                "sub": "owner",
                "client_id": client_id,
                "scope": SCOPE,
                "typ": "access",
                "jti": access_jti,
                "iat": now,
                "nbf": now,
                "exp": now + self.settings.access_token_ttl_seconds,
            },
            self.settings.signing_key_bytes(),
            algorithm=ALG,
        )
        refresh = jwt.encode(
            {
                "iss": self.settings.issuer,
                "aud": resource,
                "sub": "owner",
                "client_id": client_id,
                "scope": SCOPE,
                "typ": "refresh",
                "jti": refresh_jti,
                "iat": now,
                "nbf": now,
                "exp": now + self.settings.refresh_token_ttl_seconds,
            },
            self.settings.signing_key_bytes(),
            algorithm=ALG,
        )
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": self.settings.access_token_ttl_seconds,
            "scope": SCOPE,
        }

    def revoke(self, token: str) -> None:
        if not token:
            return
        try:
            claims = self.verify_token(token, expected_type=None, ignore_exp=True)
        except OAuthError:
            return
        ttl = (
            self.settings.refresh_token_ttl_seconds
            if claims.token_type == "refresh"
            else self.settings.access_token_ttl_seconds
        )
        self.revoke_jti(claims.jti, ttl)

    def revoke_jti(self, jti: str, ttl: int) -> None:
        self.denylist[jti] = time.time() + ttl + 60

    def looks_like_owner_secret(self, token: str) -> bool:
        return constant_time_equals(token, self.settings.owner_secret)

    def verify_token(
        self,
        token: str,
        *,
        expected_type: str | None = "access",
        ignore_exp: bool = False,
    ) -> AccessClaims:
        if not token:
            raise OAuthError("invalid_token", "missing token", status_code=401)
        if self.looks_like_owner_secret(token):
            logger.warning("owner secret presented as bearer token and rejected")
            raise OAuthError("invalid_token", "owner secret is not a bearer token", status_code=401)
        options = {"require": ["exp", "iat", "jti", "sub", "aud", "iss"]}
        if ignore_exp:
            options["verify_exp"] = False
        try:
            payload = jwt.decode(
                token,
                self.settings.signing_key_bytes(),
                algorithms=[ALG],
                audience=self.settings.resource,
                issuer=self.settings.issuer,
                options=options,
            )
        except jwt.PyJWTError as exc:
            raise OAuthError("invalid_token", "token rejected", status_code=401) from exc
        jti = str(payload.get("jti") or "")
        if jti in self.denylist:
            raise OAuthError("invalid_token", "token revoked", status_code=401)
        typ = str(payload.get("typ") or "")
        if expected_type is not None and typ != expected_type:
            raise OAuthError("invalid_token", "wrong token type", status_code=401)
        return AccessClaims(
            subject=str(payload.get("sub")),
            client_id=str(payload.get("client_id") or ""),
            scope=str(payload.get("scope") or ""),
            resource=str(payload.get("aud") or ""),
            jti=jti,
            token_type=typ,
        )

    def www_authenticate(self) -> str:
        metadata = f"{self.settings.issuer}/.well-known/oauth-protected-resource"
        return f'Bearer realm="hermes-relay", resource_metadata="{metadata}"'


def _pkce_ok(verifier: str, challenge: str) -> bool:
    if len(verifier) < 43 or len(verifier) > 128:
        return False
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


def _valid_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return True
    if parsed.scheme and parsed.scheme not in {"javascript", "data", "file"}:
        # Native / custom-scheme clients (Grok / desktop callbacks).
        return "://" in uri or parsed.scheme.isalpha()
    return False


def _safe_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "mcp-client"
    return sanitize_text(value.strip())[:80]


def _redirect(uri: str, query: dict[str, str]) -> str:
    sep = "&" if urlparse(uri).query else "?"
    return f"{uri}{sep}{urlencode(query)}"


def json_error(exc: OAuthError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.error, "error_description": exc.description},
        status_code=exc.status_code,
        headers={"Cache-Control": "no-store"},
    )


def approval_page(service: OAuthService, pending: PendingAuthorization) -> str:
    client = service.clients.get(pending.client_id)
    name = client.client_name if client else "unknown client"
    resource = service.settings.resource
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Approve hermes-relay access</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{
      margin: 0; font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: #101218; color: #e8e6e3; min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }}
    main {{
      width: min(32rem, calc(100vw - 2rem));
      background: #1a1d27; border: 1px solid #2d3140; border-radius: 12px;
      padding: 1.75rem;
    }}
    h1 {{ font-size: 1.25rem; margin: 0 0 0.75rem; }}
    p, li {{ color: #c4c0b8; line-height: 1.5; }}
    code {{ color: #f3d39a; }}
    label {{ display: block; margin: 1rem 0 0.35rem; font-size: 0.9rem; }}
    input[type=password] {{
      width: 100%; box-sizing: border-box; padding: 0.65rem 0.7rem;
      border-radius: 8px; border: 1px solid #3c4154; background: #101218; color: inherit;
    }}
    .row {{ display: flex; gap: 0.75rem; margin-top: 1.25rem; }}
    button {{
      flex: 1; padding: 0.7rem; border-radius: 8px; border: 0; cursor: pointer;
      font-weight: 600;
    }}
    .approve {{ background: #d7a13b; color: #1a1204; }}
    .deny {{ background: #3c4154; color: #e8e6e3; }}
    .warn {{ font-size: 0.85rem; color: #f0b4a4; }}
  </style>
</head>
<body>
  <main>
    <h1>Authorize local Hermes access</h1>
    <p><strong>{_html(name)}</strong> wants a token for this hermes-relay gateway.</p>
    <ul>
      <li>Resource: <code>{_html(resource)}</code></li>
      <li>This is a single-owner bridge. Approving lets that client call <code>hermes_ask</code> on this machine.</li>
    </ul>
    <p class="warn">The owner secret is not a Bearer token. Do not paste it into Grok Bot chat.</p>
    <form method="post" action="/oauth/approve">
      <input type="hidden" name="request_id" value="{_html(pending.request_id)}">
      <input type="hidden" name="csrf" value="{_html(pending.csrf)}">
      <label for="owner_secret">Owner secret</label>
      <input id="owner_secret" name="owner_secret" type="password" autocomplete="current-password" required>
      <div class="row">
        <button class="approve" type="submit" name="decision" value="approve">Approve</button>
        <button class="deny" type="submit" name="decision" value="deny">Deny</button>
      </div>
    </form>
  </main>
</body>
</html>"""


def _html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


async def handle_authorize(request: Request, service: OAuthService) -> Response:
    params = {k: v for k, v in request.query_params.items()}
    try:
        pending = service.begin_authorization(params)
    except OAuthError as exc:
        return json_error(exc)
    return html_response(approval_page(service, pending))


async def handle_approve(request: Request, service: OAuthService) -> Response:
    form = dict(await request.form())
    request_id = str(form.get("request_id") or "")
    csrf = str(form.get("csrf") or "")
    pending = service.pending.get(request_id)
    if pending is None or not constant_time_equals(csrf, pending.csrf):
        return json_error(OAuthError("invalid_request", "approval request is invalid", 400))
    try:
        location = service.approve(
            request_id,
            str(form.get("owner_secret") or ""),
            allow=str(form.get("decision")) == "approve",
        )
    except OAuthError as exc:
        return json_error(exc)
    return RedirectResponse(location, status_code=302)


async def handle_register(request: Request, service: OAuthService) -> Response:
    try:
        body = await request.json()
        if not isinstance(body, dict):
            raise OAuthError("invalid_client_metadata", "JSON object required")
        payload = service.register_client(body)
    except json.JSONDecodeError:
        return json_error(OAuthError("invalid_client_metadata", "JSON required"))
    except OAuthError as exc:
        return json_error(exc)
    return JSONResponse(payload, status_code=201)


async def handle_token(request: Request, service: OAuthService) -> Response:
    form = {str(k): str(v) for k, v in (await request.form()).items()}
    try:
        payload = service.exchange(form)
    except OAuthError as exc:
        return json_error(exc)
    return JSONResponse(payload)


async def handle_revoke(request: Request, service: OAuthService) -> Response:
    form = {str(k): str(v) for k, v in (await request.form()).items()}
    service.revoke(form.get("token") or "")
    return Response(status_code=200)
