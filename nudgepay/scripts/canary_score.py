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
        description="Compute canary score with synthetic dataset validation"
    )
    parser.add_argument(
        "--dataset", type=Path, help="Optional dataset override for validation"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=1.0,
        help="Minimum acceptable score (default: 1.0)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    dataset = _load_dataset(args.dataset) if args.dataset else None
    validation = seeding.validate_environment(dataset)

    if args.json:
        print(json.dumps(validation))
    else:
        print(f"Score: {validation['score']}")
        print(f"Dataset version: {validation['dataset_version']}")
        for scope, expected in validation["expected"].items():
            actual = validation["actual"].get(scope, 0)
            print(f"  {scope}: expected {expected} actual {actual}")
        if validation["mismatches"]:
            print("Mismatches detected:")
            for key, payload in validation["mismatches"].items():
                print(
                    f"  {key}: expected {payload['expected']} actual {payload['actual']}"
                )

    return 0 if validation["score"] >= args.threshold else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
