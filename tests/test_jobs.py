from __future__ import annotations

import asyncio

import pytest

from hermes_relay.agent import HermesRunner
from hermes_relay.config import Settings
from hermes_relay.jobs import JobError, JobStore, JobStatus


@pytest.fixture
async def store(settings: Settings) -> JobStore:
    jobs = JobStore(settings, HermesRunner(settings))
    await jobs.start()
    yield jobs
    await jobs.shutdown()


@pytest.mark.asyncio
async def test_async_ask_then_poll(store: JobStore) -> None:
    job = await store.enqueue("hello from poll")
    assert job.status in {JobStatus.QUEUED, JobStatus.RUNNING}
    for _ in range(50):
        current = await store.get(job.job_id)
        assert current is not None
        if current.status is JobStatus.SUCCEEDED:
            payload = current.public_dict()
            assert payload["status"] == "succeeded"
            assert "hello from poll" in payload["answer"]
            return
        await asyncio.sleep(0.05)
    raise AssertionError("job did not succeed in time")


@pytest.mark.asyncio
async def test_cancel_queued_or_running_job(store: JobStore) -> None:
    job = await store.enqueue("SLEEP:20")
    cancelled = await store.cancel(job.job_id)
    assert cancelled is not None
    for _ in range(50):
        current = await store.get(job.job_id)
        assert current is not None
        if current.status is JobStatus.CANCELLED:
            return
        await asyncio.sleep(0.05)
    raise AssertionError("job was not cancelled")


@pytest.mark.asyncio
async def test_queue_depth_limit(settings: Settings) -> None:
    tight = Settings(
        **{
            **settings.__dict__,
            "max_queue_depth": 1,
            "max_concurrent_jobs": 1,
        }
    )
    jobs = JobStore(tight, HermesRunner(tight))
    await jobs.start()
    try:
        first = await jobs.enqueue("SLEEP:5")
        # Wait until it is running so the next enqueue occupies the only queue slot.
        for _ in range(40):
            current = await jobs.get(first.job_id)
            if current and current.status is JobStatus.RUNNING:
                break
            await asyncio.sleep(0.05)
        second = await jobs.enqueue("SLEEP:5")
        assert second.status is JobStatus.QUEUED
        with pytest.raises(JobError, match="full"):
            await jobs.enqueue("nope")
    finally:
        await jobs.shutdown()


@pytest.mark.asyncio
async def test_sync_run(store: JobStore) -> None:
    payload = await store.run_sync("sync-me")
    assert payload["status"] == "succeeded"
    assert "sync-me" in payload["answer"]
