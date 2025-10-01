"""Schema rehearsal and lifecycle orchestration."""

from __future__ import annotations

import contextlib
import io
import logging
from dataclasses import dataclass
from pathlib import Path

import hashlib
import json
from typing import Dict

from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, func, select
from sqlmodel import Session

from .config import get_settings
from .db import engine, init_db
from .seeding import SeedSummary, seed_environment

logger = logging.getLogger(__name__)


class SchemaLifecycleError(RuntimeError):
    """Raised when a schema rehearsal step fails."""

    def __init__(self, action: str, target: str, error: Exception) -> None:
        message = f"Schema lifecycle step {action} -> {target} failed: {error}"
        super().__init__(message)
        self.action = action
        self.target = target
        self.original = error


@dataclass(slots=True)
class RehearsalStep:
    """Represents an individual step performed during schema rehearsal."""

    action: str
    target: str
    success: bool
    error: str | None = None


@dataclass(slots=True)
class SchemaRehearsalResult:
    """Structured details capturing the outcome of a rehearsal run."""

    start_revision: str | None
    downgrade_target: str
    end_revision: str | None
    steps: list[RehearsalStep]
    seed_summary: SeedSummary | None
    snapshot_checksum: str | None
    snapshot_counts: Dict[str, int]
    downgrade_completed: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "start_revision": self.start_revision,
            "downgrade_target": self.downgrade_target,
            "end_revision": self.end_revision,
            "steps": [
                {
                    "action": step.action,
                    "target": step.target,
                    "success": step.success,
                    "error": step.error,
                }
                for step in self.steps
            ],
            "seed_summary": self.seed_summary.as_dict() if self.seed_summary else None,
            "snapshot_checksum": self.snapshot_checksum,
            "snapshot_counts": dict(self.snapshot_counts),
            "downgrade_completed": self.downgrade_completed,
        }


def _alembic_config() -> Config:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    settings = get_settings()
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def _current_revision(config: Config) -> str | None:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        command.current(config, verbose=False)
    output = buffer.getvalue().strip()
    if not output:
        return None
    # Alembic may emit multiple revisions; take the last token.
    return output.split()[-1]


def _capture_snapshot_counts() -> Dict[str, int]:
    tables = (
        "adminuser",
        "user",
        "client",
        "invoice",
        "reminderlog",
        "servicetoken",
        "deploymentrecord",
        "automationexecutionrecord",
    )
    counts: Dict[str, int] = {}
    metadata = MetaData()
    with Session(engine) as session:
        for table_name in tables:
            try:
                table = Table(table_name, metadata, autoload_with=engine)
                stmt = select(func.count()).select_from(table)
                result = session.exec(stmt)
                counts[table_name] = int(result.one()[0])
            except Exception as exc:  # pragma: no cover - table may not exist yet
                logger.warning(
                    "Failed to capture snapshot count for %s: %s", table_name, exc
                )
    return counts


def rehearse_schema(
    *,
    downgrade_target: str = "base",
    apply_seeds: bool = True,
    reset_seeds: bool = True,
) -> SchemaRehearsalResult:
    """Execute a downgrade/upgrade rehearsal and optionally reseed the environment."""

    config = _alembic_config()
    start_revision = _current_revision(config)
    steps: list[RehearsalStep] = []
    seed_summary: SeedSummary | None = None
    snapshot_counts: Dict[str, int] = {}
    snapshot_checksum: str | None = None

    def _execute(action: str, target: str, runner) -> None:
        try:
            runner()
            steps.append(RehearsalStep(action=action, target=target, success=True))
        except Exception as exc:  # pragma: no cover - delegated to caller
            steps.append(
                RehearsalStep(
                    action=action,
                    target=target,
                    success=False,
                    error=str(exc),
                )
            )
            logger.exception("Schema rehearsal step failed: %s -> %s", action, target)
            raise SchemaLifecycleError(action, target, exc) from exc

    _execute("upgrade", "head", lambda: command.upgrade(config, "head"))
    _execute(
        "downgrade",
        downgrade_target,
        lambda: command.downgrade(config, downgrade_target),
    )
    _execute("upgrade", "head", lambda: command.upgrade(config, "head"))

    init_db()

    if apply_seeds:

        def _seed_runner() -> None:
            nonlocal seed_summary
            seed_summary = seed_environment(reset=reset_seeds, apply_backfill=True)
            nonlocal snapshot_counts, snapshot_checksum
            snapshot_counts = _capture_snapshot_counts()
            snapshot_checksum = hashlib.sha256(
                json.dumps(snapshot_counts, sort_keys=True).encode("utf-8")
            ).hexdigest()

        _execute("seed", "default-dataset", _seed_runner)

    end_revision = _current_revision(config)
    downgrade_completed = any(
        step.action == "downgrade" and step.success for step in steps
    )
    return SchemaRehearsalResult(
        start_revision=start_revision,
        downgrade_target=downgrade_target,
        end_revision=end_revision,
        steps=steps,
        seed_summary=seed_summary,
        snapshot_checksum=snapshot_checksum,
        snapshot_counts=snapshot_counts,
        downgrade_completed=downgrade_completed,
    )


__all__ = [
    "SchemaLifecycleError",
    "SchemaRehearsalResult",
    "RehearsalStep",
    "rehearse_schema",
]
