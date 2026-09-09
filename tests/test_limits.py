from __future__ import annotations

from hermes_relay.limits import ConcurrencyGate, SlidingWindowLimiter


def test_rate_limiter_blocks_after_limit() -> None:
    limiter = SlidingWindowLimiter()
    assert limiter.check("a", 2).allowed is True
    assert limiter.check("a", 2).allowed is True
    denied = limiter.check("a", 2)
    assert denied.allowed is False
    assert denied.retry_after_seconds >= 0


def test_concurrency_gate() -> None:
    gate = ConcurrencyGate(1)
    assert gate.try_acquire() is True
    assert gate.try_acquire() is False
    gate.release()
    assert gate.try_acquire() is True
