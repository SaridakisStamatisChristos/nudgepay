"""Database utilities."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Iterator

from alembic import command
from alembic.config import Config
from sqlmodel import Session, create_engine

from .config import get_settings

settings = get_settings()

engine_kwargs: dict[str, object] = {"pool_pre_ping": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(settings.database_url, **engine_kwargs)


def _alembic_config() -> Config:
    """Construct an Alembic configuration bound to the current settings."""

    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def init_db() -> None:
    """Ensure the schema is migrated to the latest revision."""

    command.upgrade(_alembic_config(), "head")


def get_session() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""

    with Session(engine) as session:
        yield session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope for background jobs."""

    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def transactional_session() -> Iterator[Session]:
    """Ensure work is committed or rolled back atomically."""

    with session_scope() as session:
        yield session


__all__ = ["engine", "get_session", "init_db", "session_scope", "transactional_session"]
