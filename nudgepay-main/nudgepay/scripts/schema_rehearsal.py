from __future__ import annotations

import argparse
import json

from app.schema_lifecycle import SchemaLifecycleError, rehearse_schema


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run downgrade/upgrade schema rehearsals"
    )
    parser.add_argument(
        "--target", default="base", help="Downgrade target revision (default: base)"
    )
    parser.add_argument(
        "--skip-seed", action="store_true", help="Skip reseeding after upgrade"
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    try:
        result = rehearse_schema(
            downgrade_target=args.target,
            apply_seeds=not args.skip_seed,
            reset_seeds=True,
        )
    except SchemaLifecycleError as exc:
        payload = {"error": str(exc), "action": exc.action, "target": exc.target}
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"Schema rehearsal failed: {payload['error']}")
        return 1

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
