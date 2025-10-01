import importlib

from app import chaos, payments


def test_simulate_smtp_outage(monkeypatch):
    calls = {"raised": False}

    with chaos.simulate_smtp_outage():
        try:
            from app import emailer

            emailer.send_email("to", "subject", "body")
        except ConnectionError:
            calls["raised"] = True

    assert calls["raised"] is True


def test_run_experiments_records_failures():
    results = chaos.run_experiments(
        [
            ("ok", lambda: None),
            ("boom", lambda: (_ for _ in ()).throw(RuntimeError("fail"))),
        ]
    )
    summary = {result.name: result for result in results}
    assert summary["ok"].succeeded is True
    assert summary["boom"].succeeded is False
    assert "fail" in summary["boom"].error


def test_dependency_game_day_probes(monkeypatch):
    monkeypatch.setattr(
        payments,
        "ensure_payment_link",
        lambda *args, **kwargs: "https://stripe.example/ok",
    )
    monkeypatch.setattr(
        payments, "verify_webhook", lambda *_args, **_kwargs: {"id": "evt_test"}
    )

    # Reload chaos module to ensure patched payments are used in closures
    importlib.reload(chaos)

    experiments = chaos.build_dependency_game_day()
    names = {name for name, _ in experiments}
    assert {
        "smtp_outage",
        "stripe_outage",
        "stripe_webhook_backoff",
        "stripe_payment_degradation",
        "stripe_webhook_degradation",
    }.issubset(names)

    results = chaos.run_experiments(experiments)
    assert all(result.succeeded for result in results)
