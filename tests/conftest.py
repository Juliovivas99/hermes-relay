from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from hermes_relay.config import InvokeMode, Settings

FIXTURE_HERMES = Path(__file__).parent / "fixtures" / "fake_hermes.py"


@pytest.fixture
def fake_hermes(tmp_path: Path) -> Path:
    target = tmp_path / "hermes"
    target.write_text(
        "#!/usr/bin/env python3\n"
        f"import runpy, sys\n"
        f"sys.argv[0] = 'hermes'\n"
        f"runpy.run_path({str(FIXTURE_HERMES)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    target.chmod(target.stat().st_mode | stat.S_IEXEC)
    return target


@pytest.fixture
def settings(fake_hermes: Path, tmp_path: Path) -> Settings:
    home = tmp_path / ".hermes"
    home.mkdir()
    return Settings(
        owner_secret="owner-secret-value-ok",
        public_base_url="http://127.0.0.1:8099",
        hermes_bin=fake_hermes,
        hermes_home=home,
        bind_host="127.0.0.1",
        bind_port=8099,
        token_signing_key="unit-test-token-key-32bytes-long!",
        invoke_mode=InvokeMode.CHAT_ONESHOT,
        sync_timeout_seconds=8,
        async_timeout_seconds=8,
        async_timeout_max_seconds=8,
        kill_grace_seconds=0.4,
        max_concurrent_jobs=2,
        max_queue_depth=4,
        job_ttl_seconds=60,
        max_answer_chars=200,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
        max_prompt_chars=2000,
        max_turns_default=8,
        max_turns_cap=16,
        max_request_body_bytes=32_768,
        rate_limit_mcp_per_minute=1000,
        rate_limit_oauth_per_minute=1000,
        access_token_ttl_seconds=300,
        refresh_token_ttl_seconds=3600,
        require_https_public_url=False,
    )


@pytest.fixture
def isolated_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in list(os.environ):
        if key.startswith("HERMES_") or key in {
            "OWNER_SECRET",
            "PUBLIC_BASE_URL",
            "BIND_HOST",
            "BIND_PORT",
            "TOKEN_SIGNING_KEY",
            "HERMES_BIN",
            "HERMES_HOME",
        }:
            monkeypatch.delenv(key, raising=False)
    yield
