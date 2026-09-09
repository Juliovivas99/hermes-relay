from __future__ import annotations

from pathlib import Path

from hermes_relay.agent import HermesArgvBuilder, build_child_env
from hermes_relay.config import InvokeMode, Settings


def _settings(tmp_path: Path, mode: InvokeMode = InvokeMode.CHAT_ONESHOT) -> Settings:
    binary = tmp_path / "hermes"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    return Settings(
        owner_secret="owner-secret-value-ok",
        public_base_url="http://127.0.0.1:8099",
        hermes_bin=binary,
        hermes_home=tmp_path / ".hermes",
        invoke_mode=mode,
        require_https_public_url=False,
    )


def test_chat_oneshot_argv_includes_official_flags(tmp_path: Path) -> None:
    builder = HermesArgvBuilder(_settings(tmp_path))
    plan = builder.build(
        "summarize this",
        session_id="sess-1",
        profile="work",
        max_turns=4,
    )
    assert plan.argv[1:3] == ["chat", "--oneshot"]
    assert "-q" in plan.argv
    assert plan.argv[plan.argv.index("-q") + 1] == "summarize this"
    assert plan.argv.count("summarize this") == 1
    assert "--resume" in plan.argv
    assert "sess-1" in plan.argv
    assert "--profile" in plan.argv
    assert "work" in plan.argv
    assert "--max-turns" in plan.argv
    assert "4" in plan.argv
    assert "--source" in plan.argv
    assert "hermes-relay" in plan.argv
    assert plan.session_applied is True
    assert plan.profile_applied is True
    assert plan.max_turns_applied is True


def test_top_level_z_does_not_apply_session(tmp_path: Path) -> None:
    builder = HermesArgvBuilder(_settings(tmp_path, InvokeMode.TOP_LEVEL_Z))
    plan = builder.build("hello", session_id="sess-9", profile="home")
    assert plan.argv[-2:] == ["-z", "hello"]
    assert "--resume" not in plan.argv
    assert plan.session_applied is False
    assert plan.profile_applied is True
    assert any("session_id" in note for note in plan.notes)


def test_unsafe_session_token_ignored(tmp_path: Path) -> None:
    builder = HermesArgvBuilder(_settings(tmp_path))
    plan = builder.build("hi", session_id="../etc/passwd")
    assert "--resume" not in plan.argv
    assert plan.session_applied is False


def test_max_turns_clamped(tmp_path: Path) -> None:
    builder = HermesArgvBuilder(_settings(tmp_path))
    plan = builder.build("hi", max_turns=999)
    assert plan.argv[plan.argv.index("--max-turns") + 1] == str(builder.settings.max_turns_cap)
    assert any("clamped" in note for note in plan.notes)


def test_child_env_is_minimal(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OWNER_SECRET", "should-not-leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "also-no")
    settings = _settings(tmp_path)
    env = build_child_env(settings)
    assert "OWNER_SECRET" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["HERMES_SESSION_SOURCE"] == "hermes-relay"
    assert "hermes-relay" == env["HERMES_SESSION_SOURCE"]
    assert str(settings.hermes_bin.parent) in env["PATH"]
