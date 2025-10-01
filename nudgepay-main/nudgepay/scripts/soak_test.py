"""Long-running soak tests that exercise key journeys."""

from __future__ import annotations

import argparse
import json
import time
from statistics import mean
from typing import Dict, List

try:  # pragma: no cover - allow execution via `python -m`
    from . import synthetic_monitors
except ImportError:  # pragma: no cover - direct execution fallback
    import synthetic_monitors  # type: ignore[import]


def run_soak(iterations: int, pause_seconds: float) -> Dict[str, object]:
    """Execute repeated synthetic monitors and aggregate results."""

    latencies: List[float] = []
    failures = 0
    for _ in range(iterations):
        start = time.monotonic()
        results = synthetic_monitors.run_once()
        duration = time.monotonic() - start
        latencies.append(duration)
        for status in results.values():
            if status >= 500 or status == 0:
                failures += 1
        time.sleep(pause_seconds)
    return {
        "iterations": iterations,
        "avg_latency": mean(latencies) if latencies else 0.0,
        "max_latency": max(latencies) if latencies else 0.0,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run soak tests against the deployment")
    parser.add_argument("--iterations", type=int, default=60)
    parser.add_argument("--pause", type=float, default=5.0)
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    args = parser.parse_args(argv)

    summary = run_soak(args.iterations, args.pause)

    if args.json:
        print(json.dumps(summary))
    else:
        print(
            "Soak test iterations={iterations} avg_latency={avg_latency:.3f}s "
            "max_latency={max_latency:.3f}s failures={failures}".format(**summary)
        )

    return 1 if summary["failures"] else 0


if __name__ == "__main__":  # pragma: no cover - script entrypoint
    raise SystemExit(main())
