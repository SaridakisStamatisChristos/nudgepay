import importlib

from app import config


def _reconfigure(tmp_path, monkeypatch):
    db_path = tmp_path / "seed.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    config.reset_settings_cache()

    from app import db, seeding

    importlib.reload(db)
    return importlib.reload(seeding)


def test_seed_environment_and_validate(tmp_path, monkeypatch):
    seeding = _reconfigure(tmp_path, monkeypatch)

    summary = seeding.seed_environment(reset=True, apply_backfill=True)
    assert summary.created["users"] == len(seeding.DEFAULT_DATASET["users"])
    assert summary.backfill["reminder_logs"] >= 1

    validation = seeding.validate_environment()
    assert validation["score"] == 1.0
    assert not validation["mismatches"]
