from __future__ import annotations

from pathlib import Path

import pytest

from hermes_relay.cli import cmd_serve
from hermes_relay.config import ConfigError, load_settings, validate_owner_secret, validate_public_base_url


def test_owner_secret_rejects_placeholder() -> None:
    with pytest.raises(ConfigError):
        validate_owner_secret("changeme")
    with pytest.raises(ConfigError):
        validate_owner_secret("short")


def test_public_url_requires_https_off_loopback() -> None:
    with pytest.raises(ConfigError):
        validate_public_base_url("http://example.invalid", require_https=True)
    assert validate_public_base_url("http://127.0.0.1:8099", require_https=True)


def test_serve_refuses_missing_secret(isolated_env, monkeypatch, tmp_path: Path) -> None:
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("HERMES_BIN", str(fake))
    monkeypatch.setenv("HERMES_RELAY_PUBLIC_BASE_URL", "http://127.0.0.1:8099")
    monkeypatch.setenv("HERMES_RELAY_REQUIRE_HTTPS", "0")

    class Args:
        env_file = None
        host = None
        port = None
        log_level = "INFO"

    assert cmd_serve(Args()) == 2


def test_serve_refuses_missing_url(isolated_env, monkeypatch, tmp_path: Path) -> None:
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("HERMES_BIN", str(fake))
    monkeypatch.setenv("HERMES_RELAY_OWNER_SECRET", "unit-test-owner-secret")

    class Args:
        env_file = None
        host = None
        port = None
        log_level = "INFO"

    assert cmd_serve(Args()) == 2


def test_serve_refuses_missing_hermes(isolated_env, monkeypatch) -> None:
    monkeypatch.setenv("HERMES_RELAY_OWNER_SECRET", "unit-test-owner-secret")
    monkeypatch.setenv("HERMES_RELAY_PUBLIC_BASE_URL", "http://127.0.0.1:8099")
    monkeypatch.setenv("HERMES_RELAY_REQUIRE_HTTPS", "0")
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.delenv("HERMES_BIN", raising=False)

    class Args:
        env_file = None
        host = None
        port = None
        log_level = "INFO"

    assert cmd_serve(Args()) == 2


def test_load_settings_success(isolated_env, monkeypatch, tmp_path: Path) -> None:
    fake = tmp_path / "hermes"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    fake.chmod(0o755)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_BIN", str(fake))
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_RELAY_OWNER_SECRET", "unit-test-owner-secret")
    monkeypatch.setenv("HERMES_RELAY_PUBLIC_BASE_URL", "http://127.0.0.1:8099")
    monkeypatch.setenv("HERMES_RELAY_REQUIRE_HTTPS", "0")
    settings = load_settings(require_serve=True)
    assert settings.hermes_bin.name == "hermes"
    assert settings.bind_host == "127.0.0.1"
