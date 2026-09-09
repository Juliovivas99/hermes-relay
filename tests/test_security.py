from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from hermes_relay.config import Settings
from hermes_relay.security import sanitize_text
from hermes_relay.server import create_app


def test_sanitize_redacts_paths_and_secrets() -> None:
    text = "failed at /home/ada/.hermes/config.yaml Bearer abcdef.secret"
    cleaned = sanitize_text(text)
    assert "/home/" not in cleaned
    assert "abcdef.secret" not in cleaned
    assert "<path>" in cleaned or "<redacted>" in cleaned


@pytest.mark.asyncio
async def test_invalid_host_rejected(settings: Settings) -> None:
    app = create_app(settings)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://evil.example") as client:
        response = await client.get("/healthz")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_host"


@pytest.mark.asyncio
async def test_body_limit(settings: Settings) -> None:
    tight = Settings(**{**settings.__dict__, "max_request_body_bytes": 64})
    app = create_app(tight)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8099") as client:
        response = await client.post("/oauth/register", content=b"x" * 200)
        assert response.status_code == 413
