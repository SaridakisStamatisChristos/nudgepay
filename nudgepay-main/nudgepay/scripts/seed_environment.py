from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from app import seeding


def _load_dataset(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):  # pragma: no cover - defensive
        raise ValueError("Dataset must be a JSON object")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the NudgePay environment with canonical data"
    )
    parser.add_argument("--dataset", type=Path, help="Optional JSON dataset override")
    parser.add_argument(
        "--no-backfill", action="store_true", help="Skip reminder backfill phase"
    )
    parser.add_argument(
        "--no-reset", action="store_true", help="Skip truncating existing tables"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON output"
    )
    args = parser.parse_args()

    dataset = _load_dataset(args.dataset) if args.dataset else None
    summary = seeding.seed_environment(
        dataset,
        reset=not args.no_reset,
        apply_backfill=not args.no_backfill,
    )

    output = summary.as_dict()
    if args.json:
        print(json.dumps(output))
    else:
        print(f"Dataset version: {output['dataset_version']}")
        for key, value in output["created"].items():
            print(f"Created {key}: {value}")
        for key, value in output["backfill"].items():
            print(f"Backfilled {key}: {value}")

    validation = seeding.validate_environment(dataset)
    if args.json:
        print(json.dumps({"validation": validation}))
    else:
        print(f"Validation score: {validation['score']}")
        if validation["mismatches"]:
            print("Mismatches detected:")
            for key, payload in validation["mismatches"].items():
                print(
                    f"  {key}: expected {payload['expected']} actual {payload['actual']}"
                )

    return 0 if validation["score"] >= 1.0 else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
