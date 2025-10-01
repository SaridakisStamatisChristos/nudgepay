from types import SimpleNamespace

from app import payments


def test_verify_webhook_supports_secret_rotation(monkeypatch):
    calls: list[str] = []

    class FakeWebhook:
        @staticmethod
        def construct_event(payload, sig_header, secret):
            calls.append(secret)
            if secret == "secondary":
                return {"ok": True}
            raise ValueError("invalid signature")

    monkeypatch.setattr(payments, "stripe", SimpleNamespace(Webhook=FakeWebhook))
    payments._webhook_secrets.configure("primary", ("secondary",))

    event = payments.verify_webhook("sig", b"{}")

    assert event == {"ok": True}
    assert calls == ["primary", "secondary"]


def test_webhook_rotation_manager_handles_overlap(monkeypatch):
    payments._webhook_secrets.configure("initial", ())

    def generator():
        return "rotated"

    state = payments.rotate_webhook_secret(generator)
    assert state.value == "rotated"
    assert "initial" in payments.active_webhook_secrets()

    payments.retire_webhook_secret("initial")
    active = payments.active_webhook_secrets()
    assert "initial" not in active
    assert "rotated" in active
