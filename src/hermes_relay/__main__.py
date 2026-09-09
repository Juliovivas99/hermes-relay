"""Allow `python -m hermes_relay`."""

from __future__ import annotations

from hermes_relay.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
