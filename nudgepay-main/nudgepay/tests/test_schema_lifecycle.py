import importlib

from app import config


def _reconfigure(tmp_path, monkeypatch):
    db_path = tmp_path / "schema.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    config.reset_settings_cache()

    from app import db, schema_lifecycle, seeding

    importlib.reload(db)
    importlib.reload(seeding)
    db.init_db()
    return importlib.reload(schema_lifecycle), seeding


def test_rehearse_schema_seeds_environment(tmp_path, monkeypatch):
    schema_lifecycle, seeding = _reconfigure(tmp_path, monkeypatch)

    monkeypatch.setattr(
        schema_lifecycle.command, "upgrade", lambda config, target: None
    )
    monkeypatch.setattr(
        schema_lifecycle.command, "downgrade", lambda config, target: None
    )

    result = schema_lifecycle.rehearse_schema()
    assert all(step.success for step in result.steps)
    assert result.seed_summary is not None

    validation = seeding.validate_environment()
    assert validation["score"] == 1.0
