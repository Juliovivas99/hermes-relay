"""Bounded Hermes CLI invocation: fixed argv, minimal env, process-group kill."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from dataclasses import dataclass, field
from pathlib import Path

from hermes_relay.config import InvokeMode, Settings
from hermes_relay.security import bound_text, sanitize_text, strip_ansi

logger = logging.getLogger("hermes_relay.agent")

SESSION_SOURCE = "hermes-relay"


class AgentError(RuntimeError):
    """Safe, sanitized failure from the Hermes runner."""


@dataclass(frozen=True)
class ArgvPlan:
    argv: list[str]
    session_applied: bool
    profile_applied: bool
    max_turns_applied: bool
    invoke_mode: InvokeMode
    notes: tuple[str, ...] = ()


class HermesArgvBuilder:
    """Build a fixed argv list from official Hermes CLI flags.

    Documented shapes (Nous Research CLI reference):
    - ``hermes chat --oneshot -q PROMPT`` — answer and exit; supports
      ``--resume``, ``--profile``, ``--max-turns``, ``--source``.
    - ``hermes -z PROMPT`` — scripted one-shot, final answer only.
      Session resume and ``--max-turns`` are not applied in this mode.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def build(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
    ) -> ArgvPlan:
        if not isinstance(prompt, str) or not prompt.strip():
            raise AgentError("prompt must be a non-empty string")
        if len(prompt) > self.settings.max_prompt_chars:
            raise AgentError("prompt exceeds configured maximum length")
        if "\x00" in prompt:
            raise AgentError("prompt contains a NUL byte")

        binary = str(self.settings.hermes_bin)
        notes: list[str] = []
        session_applied = False
        profile_applied = False
        max_turns_applied = False

        turns = max_turns if max_turns is not None else self.settings.max_turns_default
        if turns < 1:
            turns = 1
        if turns > self.settings.max_turns_cap:
            turns = self.settings.max_turns_cap
            notes.append("max_turns was clamped to the configured cap")

        profile_ok = bool(profile and profile.strip() and _safe_token(profile))
        session_ok = bool(session_id and session_id.strip() and _safe_token(session_id))
        if profile and not profile_ok:
            notes.append("profile ignored because it is not a safe token")
        if session_id and not session_ok:
            notes.append("session_id ignored because it is not a safe token")

        if self.settings.invoke_mode is InvokeMode.TOP_LEVEL_Z:
            argv = [binary]
            if profile_ok:
                argv.extend(["--profile", profile.strip()])  # type: ignore[union-attr]
                profile_applied = True
            argv.extend(["-z", prompt])
            if session_ok:
                notes.append(
                    "session_id is accepted by the tool schema but is not passed "
                    "in top_level_z mode; switch invoke mode to chat_oneshot to use --resume"
                )
            notes.append("max_turns is not passed in top_level_z mode")
            return ArgvPlan(
                argv=argv,
                session_applied=False,
                profile_applied=profile_applied,
                max_turns_applied=False,
                invoke_mode=InvokeMode.TOP_LEVEL_Z,
                notes=tuple(notes),
            )

        argv = [binary, "chat", "--oneshot"]
        if profile_ok:
            argv.extend(["--profile", profile.strip()])  # type: ignore[union-attr]
            profile_applied = True
        if session_ok:
            argv.extend(["--resume", session_id.strip()])  # type: ignore[union-attr]
            session_applied = True
        argv.extend(["--max-turns", str(turns)])
        max_turns_applied = True
        argv.extend(["--source", SESSION_SOURCE])
        argv.extend(["-q", prompt])
        return ArgvPlan(
            argv=argv,
            session_applied=session_applied,
            profile_applied=profile_applied,
            max_turns_applied=max_turns_applied,
            invoke_mode=InvokeMode.CHAT_ONESHOT,
            notes=tuple(notes),
        )


def _safe_token(value: str) -> bool:
    text = value.strip()
    if not text or len(text) > 128:
        return False
    return all(ch.isalnum() or ch in "-_.:@" for ch in text)


def build_child_env(settings: Settings) -> dict[str, str]:
    """Minimal environment: do not inherit the parent process environment."""
    bin_dir = str(Path(settings.hermes_bin).parent)
    path_parts = [bin_dir, "/usr/local/bin", "/usr/bin", "/bin"]
    env = {
        "PATH": os.pathsep.join(path_parts),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "HERMES_SESSION_SOURCE": SESSION_SOURCE,
        "HERMES_INTERACTIVE": "0",
    }
    if settings.hermes_home is not None:
        home = settings.hermes_home
        env["HERMES_HOME"] = str(home)
        if home.name == ".hermes":
            env["HOME"] = str(home.parent)
        else:
            env["HOME"] = str(home)
    env["HERMES_MAX_TURNS"] = str(settings.max_turns_default)
    return env


@dataclass
class RunResult:
    status: str
    answer: str = ""
    exit_code: int | None = None
    truncated: bool = False
    timed_out: bool = False
    cancelled: bool = False
    session_applied: bool = False
    profile_applied: bool = False
    max_turns_applied: bool = False
    notes: tuple[str, ...] = ()
    error: str | None = None


@dataclass
class RunningChild:
    process: asyncio.subprocess.Process
    pgid: int | None
    cancelled: asyncio.Event = field(default_factory=asyncio.Event)


class HermesRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.builder = HermesArgvBuilder(settings)
        self._children: dict[int, RunningChild] = {}

    def plan(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
    ) -> ArgvPlan:
        return self.builder.build(
            prompt, session_id=session_id, profile=profile, max_turns=max_turns
        )

    async def run(
        self,
        prompt: str,
        *,
        session_id: str | None = None,
        profile: str | None = None,
        max_turns: int | None = None,
        timeout: float | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> RunResult:
        plan = self.plan(prompt, session_id=session_id, profile=profile, max_turns=max_turns)
        timeout = float(timeout if timeout is not None else self.settings.sync_timeout_seconds)
        env = build_child_env(self.settings)
        child: RunningChild | None = None
        stdout = b""
        stderr = b""
        try:
            process = await asyncio.create_subprocess_exec(
                *plan.argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                start_new_session=True,
                cwd=str(self.settings.hermes_home) if self.settings.hermes_home else None,
            )
            try:
                pgid = os.getpgid(process.pid)
            except OSError:
                pgid = None
            child = RunningChild(process=process, pgid=pgid)
            self._children[process.pid] = child

            async def _watch_cancel() -> None:
                if cancel_event is None:
                    return
                await cancel_event.wait()
                child.cancelled.set()
                await self._terminate(child)

            watcher = asyncio.create_task(_watch_cancel())
            try:
                stdout, stderr = await asyncio.wait_for(
                    _read_bounded(
                        process,
                        max_stdout=self.settings.max_stdout_bytes,
                        max_stderr=self.settings.max_stderr_bytes,
                    ),
                    timeout=timeout,
                )
                await process.wait()
            except asyncio.TimeoutError:
                await self._terminate(child)
                await process.wait()
                return RunResult(
                    status="timed_out",
                    timed_out=True,
                    truncated=True,
                    session_applied=plan.session_applied,
                    profile_applied=plan.profile_applied,
                    max_turns_applied=plan.max_turns_applied,
                    notes=plan.notes,
                    error="Hermes invocation exceeded the hard timeout",
                )
            finally:
                watcher.cancel()
                try:
                    await watcher
                except (asyncio.CancelledError, Exception):
                    pass

            if child.cancelled.is_set() or (cancel_event is not None and cancel_event.is_set()):
                return RunResult(
                    status="cancelled",
                    cancelled=True,
                    session_applied=plan.session_applied,
                    profile_applied=plan.profile_applied,
                    max_turns_applied=plan.max_turns_applied,
                    notes=plan.notes,
                    error="job cancelled",
                )

            answer, truncated = _decode_answer(stdout, self.settings.max_answer_chars)
            if process.returncode not in (0, None):
                err = sanitize_text(_decode_raw(stderr, self.settings.max_stderr_bytes))
                err = bound_text(err, 500)[0] or "Hermes exited unsuccessfully"
                return RunResult(
                    status="failed",
                    answer=answer,
                    exit_code=process.returncode,
                    truncated=truncated,
                    session_applied=plan.session_applied,
                    profile_applied=plan.profile_applied,
                    max_turns_applied=plan.max_turns_applied,
                    notes=plan.notes,
                    error=err,
                )
            return RunResult(
                status="succeeded",
                answer=answer,
                exit_code=process.returncode or 0,
                truncated=truncated,
                session_applied=plan.session_applied,
                profile_applied=plan.profile_applied,
                max_turns_applied=plan.max_turns_applied,
                notes=plan.notes,
            )
        except AgentError:
            raise
        except FileNotFoundError as exc:
            logger.warning("hermes binary missing at run time: %s", exc)
            raise AgentError("Hermes binary is not available") from exc
        except Exception as exc:
            logger.warning("hermes run failed: %s", type(exc).__name__)
            raise AgentError("Hermes invocation failed") from exc
        finally:
            if child is not None:
                self._children.pop(child.process.pid, None)
                if child.process.returncode is None:
                    await self._terminate(child)

    async def _terminate(self, child: RunningChild) -> None:
        proc = child.process
        if proc.returncode is not None:
            return
        target = child.pgid if child.pgid is not None else proc.pid
        try:
            if child.pgid is not None:
                os.killpg(child.pgid, signal.SIGTERM)
            else:
                proc.terminate()
        except ProcessLookupError:
            return
        except PermissionError:
            logger.warning("lacked permission to signal Hermes child")
        try:
            await asyncio.wait_for(proc.wait(), timeout=self.settings.kill_grace_seconds)
            return
        except asyncio.TimeoutError:
            pass
        try:
            if child.pgid is not None:
                os.killpg(child.pgid, signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            logger.warning("failed to reap Hermes child pid=%s", target)

    async def shutdown(self) -> None:
        children = list(self._children.values())
        for child in children:
            await self._terminate(child)


async def _read_bounded(
    process: asyncio.subprocess.Process,
    *,
    max_stdout: int,
    max_stderr: int,
) -> tuple[bytes, bytes]:
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_done = False
    stderr_done = False

    async def _pump(stream: asyncio.StreamReader, buf: bytearray, limit: int, which: str) -> None:
        nonlocal stdout_done, stderr_done
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            remaining = limit - len(buf)
            if remaining > 0:
                buf.extend(chunk[:remaining])
            # Discard the rest to keep the pipe from filling, but do not store it.
        if which == "stdout":
            stdout_done = True
        else:
            stderr_done = True

    await asyncio.gather(
        _pump(process.stdout, stdout_buf, max_stdout, "stdout"),
        _pump(process.stderr, stderr_buf, max_stderr, "stderr"),
    )
    return bytes(stdout_buf), bytes(stderr_buf)


def _decode_raw(data: bytes, max_bytes: int) -> str:
    clipped = data[:max_bytes]
    return clipped.decode("utf-8", errors="replace")


def _decode_answer(data: bytes, max_chars: int) -> tuple[str, bool]:
    text = sanitize_text(strip_ansi(_decode_raw(data, len(data))))
    text = text.replace("\r\n", "\n").strip()
    return bound_text(text, max_chars)
