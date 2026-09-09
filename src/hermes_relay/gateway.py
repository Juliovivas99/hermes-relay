"""MCP tool surface for hermes-relay."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.mcpserver import MCPServer

from hermes_relay import __version__
from hermes_relay.agent import AgentError
from hermes_relay.jobs import JobError, JobStore
from hermes_relay.security import sanitize_text

logger = logging.getLogger("hermes_relay.gateway")

INSTRUCTIONS = (
    "hermes-relay exposes a local Hermes Agent to remote MCP clients such as Grok Bot. "
    "This is one-way: Grok Bot may call Hermes. Hermes cannot call Grok Bot built-ins. "
    "Always send one brief visible handoff line before using these tools. "
    "Never impersonate Hermes. Never ask the operator for secrets in chat. "
    "Prefer hermes_ask with async_mode=true, then hermes_poll."
)


def build_mcp_server(jobs: JobStore) -> MCPServer:
    server = MCPServer(
        "hermes-relay",
        instructions=INSTRUCTIONS,
    )

    @server.tool(
        name="hermes_ask",
        description=(
            "Send a prompt to the operator's local Hermes Agent. "
            "Default async_mode=true enqueues a job and returns {job_id, status} immediately. "
            "Set async_mode=false to wait for a bounded synchronous answer."
        ),
    )
    async def hermes_ask(
        prompt: str,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
        async_mode: bool = True,
    ) -> dict[str, Any]:
        prompt = (prompt or "").strip()
        if not prompt:
            return {"status": "failed", "error": "prompt is required"}
        try:
            if async_mode:
                job = await jobs.enqueue(
                    prompt,
                    session_id=session_id,
                    profile=profile,
                    max_turns=max_turns,
                )
                return {"job_id": job.job_id, "status": job.status.value}
            return await jobs.run_sync(
                prompt,
                session_id=session_id,
                profile=profile,
                max_turns=max_turns,
            )
        except (JobError, AgentError) as exc:
            return {"status": "failed", "error": str(exc)}

    @server.tool(
        name="hermes_poll",
        description="Read status (and answer, when finished) for a hermes_ask job.",
    )
    async def hermes_poll(job_id: str) -> dict[str, Any]:
        job = await jobs.get(job_id)
        if job is None:
            return {"status": "failed", "error": "unknown job_id"}
        return job.public_dict()

    @server.tool(
        name="hermes_cancel",
        description="Cancel a queued or running Hermes job and kill its process group.",
    )
    async def hermes_cancel(job_id: str) -> dict[str, Any]:
        job = await jobs.cancel(job_id)
        if job is None:
            return {"status": "failed", "error": "unknown job_id"}
        return {"job_id": job.job_id, "status": job.status.value}

    @server.tool(
        name="hermes_status",
        description="Filtered, non-sensitive Hermes and gateway health. Never includes secrets or home paths.",
    )
    async def hermes_status() -> dict[str, Any]:
        settings = jobs.settings
        counts = jobs.counts()
        return {
            "gateway": "hermes-relay",
            "version": __version__,
            "hermes": {
                "binary_name": settings.hermes_bin.name,
                "found": True,
                "invoke_mode": settings.invoke_mode.value,
                "home_configured": settings.hermes_home is not None,
            },
            "jobs": {
                "queued": counts.get("queued", 0),
                "running": counts.get("running", 0),
                "succeeded": counts.get("succeeded", 0),
                "failed": counts.get("failed", 0),
                "cancelled": counts.get("cancelled", 0),
                "timed_out": counts.get("timed_out", 0),
                "max_concurrent": settings.max_concurrent_jobs,
                "max_queue": settings.max_queue_depth,
            },
            "limits": {
                "sync_timeout_seconds": settings.sync_timeout_seconds,
                "async_timeout_seconds": settings.async_timeout_seconds,
                "max_answer_chars": settings.max_answer_chars,
                "max_turns_cap": settings.max_turns_cap,
            },
            "bind": "loopback",
            "oauth": {"configured": True},
            "public_url_configured": bool(settings.public_base_url),
            "direction": "grok_bot_to_hermes",
            "notes": [
                "This gateway lets Grok Bot call local Hermes. Hermes cannot call Grok Bot built-ins.",
            ],
        }

    return server


def safe_tool_error(exc: BaseException) -> dict[str, Any]:
    return {"status": "failed", "error": sanitize_text(str(exc))}
