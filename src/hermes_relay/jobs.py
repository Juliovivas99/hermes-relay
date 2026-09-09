"""In-memory async job store for Hermes invocations."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from hermes_relay.agent import AgentError, HermesRunner, RunResult
from hermes_relay.config import Settings
from hermes_relay.limits import ConcurrencyGate

logger = logging.getLogger("hermes_relay.jobs")


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


TERMINAL = {
    JobStatus.SUCCEEDED,
    JobStatus.FAILED,
    JobStatus.CANCELLED,
    JobStatus.TIMED_OUT,
}


class JobError(RuntimeError):
    pass


@dataclass
class Job:
    job_id: str
    prompt: str
    session_id: str | None
    profile: str | None
    max_turns: int | None
    status: JobStatus = JobStatus.QUEUED
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    result: RunResult | None = None
    error: str | None = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def touch(self) -> None:
        self.updated_at = time.time()

    def public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "status": self.status.value,
        }
        if self.result is not None:
            payload["answer"] = self.result.answer
            payload["truncated"] = self.result.truncated
            payload["session_applied"] = self.result.session_applied
            payload["profile_applied"] = self.result.profile_applied
            payload["max_turns_applied"] = self.result.max_turns_applied
            if self.result.notes:
                payload["notes"] = list(self.result.notes)
            if self.result.exit_code is not None:
                payload["exit_code"] = self.result.exit_code
        if self.error:
            payload["error"] = self.error
        elif self.result is not None and self.result.error:
            payload["error"] = self.result.error
        return payload


class JobStore:
    def __init__(self, settings: Settings, runner: HermesRunner) -> None:
        self.settings = settings
        self.runner = runner
        self._jobs: dict[str, Job] = {}
        self._lock = asyncio.Lock()
        self._worker_task: asyncio.Task[None] | None = None
        self._wakeup = asyncio.Event()
        self._closed = False
        self.gate = ConcurrencyGate(settings.max_concurrent_jobs)

    async def start(self) -> None:
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker_loop(), name="hermes-relay-jobs")

    async def shutdown(self) -> None:
        self._closed = True
        self._wakeup.set()
        async with self._lock:
            for job in self._jobs.values():
                if job.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
                    job.cancel_event.set()
                    job.status = JobStatus.CANCELLED
                    job.error = "gateway shutting down"
                    job.touch()
        await self.runner.shutdown()
        if self._worker_task is not None:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except (asyncio.CancelledError, Exception):
                pass
            self._worker_task = None

    def counts(self) -> dict[str, int]:
        tallies = {status.value: 0 for status in JobStatus}
        for job in self._jobs.values():
            tallies[job.status.value] += 1
        return tallies

    async def enqueue(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
    ) -> Job:
        self._purge_locked(time.time())
        async with self._lock:
            queued = sum(1 for j in self._jobs.values() if j.status is JobStatus.QUEUED)
            if queued >= self.settings.max_queue_depth:
                raise JobError("job queue is full")
            job = Job(
                job_id=str(uuid4()),
                prompt=prompt,
                session_id=session_id,
                profile=profile,
                max_turns=max_turns,
            )
            self._jobs[job.job_id] = job
        self._wakeup.set()
        logger.info("job queued", extra={"job_id": job.job_id, "prompt_chars": len(prompt)})
        return job

    async def get(self, job_id: str) -> Job | None:
        self._purge_locked(time.time())
        return self._jobs.get(job_id)

    async def cancel(self, job_id: str) -> Job | None:
        job = self._jobs.get(job_id)
        if job is None:
            return None
        if job.status in TERMINAL:
            return job
        job.cancel_event.set()
        if job.status is JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            job.error = "job cancelled"
            job.touch()
        logger.info("job cancel requested", extra={"job_id": job.job_id})
        return job

    async def run_sync(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        if not self.gate.try_acquire():
            raise JobError("too many concurrent Hermes runs")
        try:
            result = await self.runner.run(
                prompt,
                session_id=session_id,
                profile=profile,
                max_turns=max_turns,
                timeout=self.settings.sync_timeout_seconds,
            )
            return _result_payload(result)
        except AgentError as exc:
            return {"status": "failed", "error": str(exc)}
        finally:
            self.gate.release()

    def _purge_locked(self, now: float) -> None:
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.status in TERMINAL and (now - job.updated_at) > self.settings.job_ttl_seconds
        ]
        for job_id in expired:
            job = self._jobs.pop(job_id, None)
            if job is not None:
                job.prompt = ""

    async def _worker_loop(self) -> None:
        while not self._closed:
            job = await self._next_queued()
            if job is None:
                self._wakeup.clear()
                try:
                    await asyncio.wait_for(self._wakeup.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    self._purge_locked(time.time())
                continue
            asyncio.create_task(self._execute(job), name=f"hermes-job-{job.job_id}")

    async def _next_queued(self) -> Job | None:
        running = sum(1 for j in self._jobs.values() if j.status is JobStatus.RUNNING)
        if running >= self.settings.max_concurrent_jobs:
            return None
        async with self._lock:
            for job in self._jobs.values():
                if job.status is JobStatus.QUEUED and not job.cancel_event.is_set():
                    job.status = JobStatus.RUNNING
                    job.touch()
                    return job
        return None

    async def _execute(self, job: Job) -> None:
        if job.cancel_event.is_set():
            job.status = JobStatus.CANCELLED
            job.error = "job cancelled"
            job.touch()
            return
        if not self.gate.try_acquire():
            job.status = JobStatus.QUEUED
            job.touch()
            self._wakeup.set()
            return
        try:
            result = await self.runner.run(
                job.prompt,
                session_id=job.session_id,
                profile=job.profile,
                max_turns=job.max_turns,
                timeout=min(self.settings.async_timeout_seconds, self.settings.async_timeout_max_seconds),
                cancel_event=job.cancel_event,
            )
            job.result = result
            job.status = JobStatus(result.status)
            job.error = result.error
            job.prompt = ""
            job.touch()
            logger.info("job finished", extra={"job_id": job.job_id, "status": job.status.value})
        except AgentError as exc:
            job.status = JobStatus.FAILED
            job.error = str(exc)
            job.prompt = ""
            job.touch()
        except Exception:
            logger.exception("job crashed", extra={"job_id": job.job_id})
            job.status = JobStatus.FAILED
            job.error = "internal job failure"
            job.prompt = ""
            job.touch()
        finally:
            self.gate.release()
            self._wakeup.set()


def _result_payload(result: RunResult) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": result.status,
        "answer": result.answer,
        "truncated": result.truncated,
        "session_applied": result.session_applied,
        "profile_applied": result.profile_applied,
        "max_turns_applied": result.max_turns_applied,
    }
    if result.notes:
        payload["notes"] = list(result.notes)
    if result.error:
        payload["error"] = result.error
    if result.exit_code is not None:
        payload["exit_code"] = result.exit_code
    return payload
