from __future__ import annotations

from pathlib import Path

from hermes_relay.cli import cmd_init, collect_doctor_checks


def test_doctor_reports_missing_secret_without_leaking(isolated_env, monkeypatch, tmp_path: Path) -> None:
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{tmp_path}")
    monkeypatch.setenv("HERMES_BIN", str(fake))
    checks = {c.name: c for c in collect_doctor_checks()}
    assert checks["hermes_binary"].ok is True
    assert checks["owner_secret"].ok is False
    joined = " ".join(c.detail for c in checks.values())
    assert "owner-secret-value" not in joined


def test_doctor_ok_when_required_env_present(isolated_env, monkeypatch, tmp_path: Path) -> None:
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("HERMES_BIN", str(fake))
    monkeypatch.setenv("HERMES_RELAY_OWNER_SECRET", "unit-test-owner-secret")
    monkeypatch.setenv("HERMES_RELAY_PUBLIC_BASE_URL", "http://127.0.0.1:8099")
    monkeypatch.setenv("HERMES_RELAY_REQUIRE_HTTPS", "0")
    checks = {c.name: c for c in collect_doctor_checks()}
    assert checks["owner_secret"].ok is True
    assert checks["public_base_url"].ok is True
    assert "unit-test-owner-secret" not in checks["owner_secret"].detail


def test_init_writes_mode_0600(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"

    class Args:
        force = False

    Args.path = str(env_path)

    assert cmd_init(Args()) == 0
    assert env_path.is_file()
    assert (env_path.stat().st_mode & 0o777) == 0o600
    text = env_path.read_text(encoding="utf-8")
    assert "HERMES_RELAY_OWNER_SECRET=" in text
    assert "changeme" not in text
