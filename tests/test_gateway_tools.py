from __future__ import annotations

import asyncio

import pytest

from hermes_relay.agent import HermesRunner
from hermes_relay.config import Settings
from hermes_relay.gateway import build_mcp_server
from hermes_relay.jobs import JobStore


@pytest.mark.asyncio
async def test_tools_ask_poll_cancel(settings: Settings) -> None:
    jobs = JobStore(settings, HermesRunner(settings))
    await jobs.start()
    server = build_mcp_server(jobs)
    try:
        ask = server._tool_manager.get_tool("hermes_ask")
        poll = server._tool_manager.get_tool("hermes_poll")
        cancel = server._tool_manager.get_tool("hermes_cancel")

        queued = await ask.fn(prompt="tool-hello", async_mode=True)
        assert queued["status"] in {"queued", "running"}
        job_id = queued["job_id"]

        answer = None
        for _ in range(50):
            payload = await poll.fn(job_id=job_id)
            if payload["status"] == "succeeded":
                answer = payload["answer"]
                break
            await asyncio.sleep(0.05)
        assert answer is not None
        assert "tool-hello" in answer

        sleeping = await ask.fn(prompt="SLEEP:20", async_mode=True)
        cancelled = await cancel.fn(job_id=sleeping["job_id"])
        assert cancelled["status"] in {"cancelled", "running"}
        for _ in range(50):
            payload = await poll.fn(job_id=sleeping["job_id"])
            if payload["status"] == "cancelled":
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("cancel did not finish")
    finally:
        await jobs.shutdown()
