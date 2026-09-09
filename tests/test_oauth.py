from __future__ import annotations

import base64
import hashlib
import secrets

import pytest
from httpx import ASGITransport, AsyncClient

from hermes_relay.config import Settings
from hermes_relay.oauth import OAuthService
from hermes_relay.server import create_app


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def app(settings: Settings):
    return create_app(settings, require_auth=True)


@pytest.mark.asyncio
async def test_mcp_requires_bearer_and_rejects_owner_secret(
    app, settings: Settings
) -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8099") as client:
        bare = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert bare.status_code == 401
        assert "resource_metadata" in bare.headers.get("www-authenticate", "")

        secret = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
            headers={"Authorization": f"Bearer {settings.owner_secret}"},
        )
        assert secret.status_code == 401
        assert "owner secret" in secret.json()["error_description"]


@pytest.mark.asyncio
async def test_oauth_happy_path_and_revoke(app, settings: Settings) -> None:
    verifier, challenge = _pkce()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8099") as client:
        meta = await client.get("/.well-known/oauth-authorization-server")
        assert meta.status_code == 200
        assert meta.json()["code_challenge_methods_supported"] == ["S256"]

        pr = await client.get("/.well-known/oauth-protected-resource")
        assert pr.json()["resource"] == settings.resource

        created = await client.post(
            "/oauth/register",
            json={
                "client_name": "Grok Bot",
                "redirect_uris": ["https://bot.example/oauth/callback"],
                "token_endpoint_auth_method": "none",
            },
        )
        assert created.status_code == 201
        client_id = created.json()["client_id"]

        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://bot.example/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "xyz",
                "resource": settings.resource,
            },
        )
        assert authorize.status_code == 200
        assert "Owner secret" in authorize.text

        oauth: OAuthService = app.state.relay.oauth
        pending = next(iter(oauth.pending.values()))

        denied_wrong = await client.post(
            "/oauth/approve",
            data={
                "request_id": pending.request_id,
                "csrf": pending.csrf,
                "owner_secret": "definitely-not-the-secret",
                "decision": "approve",
            },
        )
        assert denied_wrong.status_code == 403

        approved = await client.post(
            "/oauth/approve",
            data={
                "request_id": pending.request_id,
                "csrf": pending.csrf,
                "owner_secret": settings.owner_secret,
                "decision": "approve",
            },
            follow_redirects=False,
        )
        assert approved.status_code == 302
        location = approved.headers["location"]
        assert "code=" in location
        code = location.split("code=")[1].split("&")[0]

        token = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://bot.example/oauth/callback",
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": settings.resource,
            },
        )
        assert token.status_code == 200
        access = token.json()["access_token"]
        refresh = token.json()["refresh_token"]

        async with app.router.lifespan_context(app):
            ping = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0"},
                    },
                },
                headers={
                    "Authorization": f"Bearer {access}",
                    "Accept": "application/json, text/event-stream",
                },
            )
        assert ping.status_code == 200

        revoked = await client.post("/oauth/revoke", data={"token": access})
        assert revoked.status_code == 200
        after = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "ping"},
            headers={"Authorization": f"Bearer {access}"},
        )
        assert after.status_code == 401

        rotated = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh,
                "client_id": client_id,
            },
        )
        assert rotated.status_code == 200
        assert rotated.json()["access_token"] != access
