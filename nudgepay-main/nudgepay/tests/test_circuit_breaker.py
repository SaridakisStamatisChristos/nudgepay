from app.circuit_breaker import CircuitBreaker


def test_circuit_breaker_memory_fallback(monkeypatch):
    baseline = 1000.0
    monkeypatch.setattr("app.circuit_breaker.time.time", lambda: baseline)
    breaker = CircuitBreaker(
        "unit-test",
        failure_threshold=2,
        reset_after_seconds=1,
        use_redis=False,
    )

    assert breaker.is_open() is False
    breaker.record_failure()
    assert breaker.is_open() is False
    breaker.record_failure()
    assert breaker.is_open() is True

    breaker.record_success()
    assert breaker.is_open() is False

    breaker.record_failure()
    breaker.record_failure()
    assert breaker.is_open() is True

    # advance past reset window
    monkeypatch.setattr("app.circuit_breaker.time.time", lambda: baseline + 2)
    assert breaker.is_open() is False
