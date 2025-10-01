"""CLI helpers for recording deployment ledger events."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from sqlmodel import Session

from ..app import deployments
from ..app.db import engine


def _load_metadata(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
        if isinstance(loaded, dict):
            return {str(k): v for k, v in loaded.items()}
    except json.JSONDecodeError as exc:  # pragma: no cover - user input
        raise SystemExit(f"Invalid metadata JSON: {exc}") from exc
    raise SystemExit("Metadata must be a JSON object")


def _with_session() -> Session:
    return Session(engine)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deployment ledger helper")
    subcommands = parser.add_subparsers(dest="command", required=True)

    start_parser = subcommands.add_parser("start", help="Record the start of a deployment")
    start_parser.add_argument("--environment", required=True)
    start_parser.add_argument("--build-sha", required=True)
    start_parser.add_argument("--initiated-by", required=True)
    start_parser.add_argument("--metadata", help="JSON payload with extra metadata")

    complete_parser = subcommands.add_parser("complete", help="Finalize a deployment entry")
    complete_parser.add_argument("--deployment-id", type=int, required=True)
    complete_parser.add_argument("--status", required=True)
    complete_parser.add_argument("--synthetic-gate", required=True)
    complete_parser.add_argument("--rollback", action="store_true")
    complete_parser.add_argument("--notes")
    complete_parser.add_argument("--metadata", help="JSON payload with extra metadata")

    args = parser.parse_args(argv)

    if args.command == "start":
        metadata = _load_metadata(args.metadata)
        with _with_session() as session:
            record = deployments.start_deployment(
                environment=args.environment,
                build_sha=args.build_sha,
                initiated_by=args.initiated_by,
                metadata=metadata,
                session=session,
            )
            session.commit()
        print(record.id)
        return 0

    if args.command == "complete":
        metadata = _load_metadata(args.metadata)
        with _with_session() as session:
            deployments.finalize_deployment(
                deployment_id=args.deployment_id,
                status=args.status,
                synthetic_gate=args.synthetic_gate,
                rollback_triggered=bool(args.rollback),
                notes=args.notes,
                metadata=metadata,
                session=session,
            )
            session.commit()
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":  # pragma: no cover - script entrypoint
    sys.exit(main())
