from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

RUNBOOK_PATH = (
    Path(__file__).resolve().parents[1] / "ops" / "runbooks" / "storage_backends.json"
)


def _load_runbooks() -> dict[str, Any]:
    if not RUNBOOK_PATH.exists():  # pragma: no cover - defensive
        raise FileNotFoundError(f"Runbook catalog missing at {RUNBOOK_PATH}")
    data = json.loads(RUNBOOK_PATH.read_text())
    if not isinstance(data, dict):  # pragma: no cover - defensive
        raise ValueError("Runbook catalog must be a JSON object")
    return data


def simulate_failover(backend: str, region: str) -> dict[str, Any]:
    runbooks = _load_runbooks()
    if backend not in runbooks:
        raise KeyError(f"Backend '{backend}' not defined in runbook catalog")

    spec = runbooks[backend]
    allowed_regions = spec.get("regions", [])
    if allowed_regions and region not in allowed_regions:
        raise ValueError(f"Region {region} not configured for {backend}")

    steps = [
        step.format(region=region, backend=backend) for step in spec.get("steps", [])
    ]
    validations = [
        check.format(region=region, backend=backend)
        for check in spec.get("validation", [])
    ]

    return {
        "backend": backend,
        "region": region,
        "description": spec.get("description", ""),
        "steps": steps,
        "validation": validations,
        "status": "validated",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Simulate multi-region storage failover"
    )
    parser.add_argument(
        "--backend", required=True, help="Backend identifier from the runbook catalog"
    )
    parser.add_argument(
        "--region", required=True, help="Region to promote during failover"
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    try:
        payload = simulate_failover(args.backend, args.region)
    except Exception as exc:
        if args.json:
            print(
                json.dumps(
                    {"error": str(exc), "backend": args.backend, "region": args.region}
                )
            )
        else:
            print(f"Failover simulation failed: {exc}")
        return 1

    if args.json:
        print(json.dumps(payload))
    else:
        print(f"Backend: {payload['backend']}")
        print(f"Region promoted: {payload['region']}")
        print("Runbook steps:")
        for step in payload["steps"]:
            print(f"  - {step}")
        print("Validation checks:")
        for check in payload["validation"]:
            print(f"  - {check}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
