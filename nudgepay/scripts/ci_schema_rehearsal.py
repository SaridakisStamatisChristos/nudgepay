"""Run schema rehearsal with sensible defaults and graceful degradation."""
from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy.exc import OperationalError

from app.schema_lifecycle import SchemaLifecycleError, rehearse_schema

from . import ci_env


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run downgrade/upgrade schema rehearsals")
    parser.add_argument("--target", default="base", help="Downgrade target revision (default: base)")
    parser.add_argument("--skip-seed", action="store_true", help="Skip reseeding after upgrade")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    ci_env.apply_ci_environment_defaults()
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        result = rehearse_schema(
            downgrade_target=args.target,
            apply_seeds=not args.skip_seed,
            reset_seeds=True,
        )
    except SchemaLifecycleError as exc:
        if isinstance(exc.original, OperationalError):
            message = "Schema rehearsal skipped: database unavailable (OperationalError)."
            if args.json:
                print(json.dumps({"skipped": True, "reason": message}))
            else:
                print(message, file=sys.stderr)
            return 0
        payload = {"error": str(exc), "action": exc.action, "target": exc.target}
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"Schema rehearsal failed: {payload['error']}")
        return 1
    except OperationalError as exc:
        message = "Schema rehearsal skipped: database unavailable (OperationalError)."
        if args.json:
            print(json.dumps({"skipped": True, "reason": message}))
        else:
            print(f"{message} {exc}", file=sys.stderr)
        return 0

    output = result.as_dict()
    if args.json:
        print(json.dumps(output))
    else:
        print(f"Start revision: {output['start_revision']}")
        print(f"End revision: {output['end_revision']}")
        for step in output["steps"]:
            status = "ok" if step["success"] else f"failed: {step['error']}"
            print(f"{step['action']} -> {step['target']}: {status}")
        if output["seed_summary"]:
            print("Seed summary:")
            for key, value in output["seed_summary"]["created"].items():
                print(f"  created {key}: {value}")
            for key, value in output["seed_summary"]["backfill"].items():
                print(f"  backfill {key}: {value}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
