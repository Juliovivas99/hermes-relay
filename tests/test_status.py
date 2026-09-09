from __future__ import annotations

import pytest

from hermes_relay.agent import HermesRunner
from hermes_relay.config import Settings
from hermes_relay.gateway import build_mcp_server
from hermes_relay.jobs import JobStore


@pytest.mark.asyncio
async def test_status_omits_sensitive_fields(settings: Settings) -> None:
    jobs = JobStore(settings, HermesRunner(settings))
    server = build_mcp_server(jobs)
    tool = server._tool_manager.get_tool("hermes_status")
    payload = await tool.fn()
    dumped = str(payload)
    assert settings.owner_secret not in dumped
    assert str(settings.hermes_home) not in dumped
    assert "token" not in dumped.lower() or payload["oauth"]["configured"] is True
    assert "/home/" not in dumped
    assert payload["hermes"]["binary_name"] == settings.hermes_bin.name
    assert payload["direction"] == "grok_bot_to_hermes"
    assert payload["bind"] == "loopback"
