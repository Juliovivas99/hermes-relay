from __future__ import annotations

import asyncio

import pytest

from hermes_relay.agent import HermesRunner
from hermes_relay.config import Settings


@pytest.mark.asyncio
async def test_runner_returns_bounded_answer(settings: Settings) -> None:
    runner = HermesRunner(settings)
    result = await runner.run("hello world")
    assert result.status == "succeeded"
    assert "hello world" in result.answer
    assert "\x1b" not in result.answer


@pytest.mark.asyncio
async def test_runner_strips_ansi_and_paths(settings: Settings) -> None:
    runner = HermesRunner(settings)
    ansi = await runner.run("ANSI")
    assert ansi.answer == "red answer"
    leaked = await runner.run("PATH_LEAK")
    assert "/home/" not in leaked.answer
    assert "super-secret-token" not in leaked.answer
    assert "<path>" in leaked.answer or "<redacted>" in leaked.answer


@pytest.mark.asyncio
async def test_runner_bounds_answer_length(settings: Settings) -> None:
    runner = HermesRunner(settings)
    result = await runner.run("BIG:500")
    assert result.truncated is True
    assert len(result.answer) <= settings.max_answer_chars


@pytest.mark.asyncio
async def test_runner_timeout_kills_child(settings: Settings) -> None:
    runner = HermesRunner(settings)
    result = await runner.run("SLEEP:20", timeout=0.5)
    assert result.status == "timed_out"
    assert result.timed_out is True


@pytest.mark.asyncio
async def test_runner_cancel_kills_child(settings: Settings) -> None:
    runner = HermesRunner(settings)
    cancel = asyncio.Event()

    async def _cancel_soon() -> None:
        await asyncio.sleep(0.2)
        cancel.set()

    task = asyncio.create_task(_cancel_soon())
    result = await runner.run("SLEEP:20", timeout=8, cancel_event=cancel)
    await task
    assert result.status == "cancelled"
    assert result.cancelled is True


@pytest.mark.asyncio
async def test_runner_does_not_inherit_parent_secrets(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OWNER_SECRET", "parent-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "amazon")
    runner = HermesRunner(settings)
    result = await runner.run("ECHO_ENV")
    assert result.status == "succeeded"
    assert "OWNER_SECRET" not in result.answer
    assert "AWS_SECRET_ACCESS_KEY" not in result.answer
    assert "HERMES_SESSION_SOURCE" in result.answer
