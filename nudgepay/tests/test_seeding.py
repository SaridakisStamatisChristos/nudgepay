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


def test_ensure_admin_schema_reflects_legacy_sqlite_columns(tmp_path):
    from sqlalchemy import create_engine, inspect, text
    from sqlmodel import Session
    from app import seeding

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE adminuser (id INTEGER PRIMARY KEY)"))

    with Session(engine) as session:
        seeding._ensure_admin_schema(session)
        session.commit()

    columns = {column["name"] for column in inspect(engine).get_columns("adminuser")}
    assert {"role", "permissions", "external_id", "federated_providers", "hardware_key_fingerprints"} <= columns
