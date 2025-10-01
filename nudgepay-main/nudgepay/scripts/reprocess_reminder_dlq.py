#!/usr/bin/env python3
"""Drain reminder dead-letter jobs and emit a summary to stdout."""

from __future__ import annotations

import argparse
import json

from app.db import init_db
from app.tasks import requeue_failed_reminders


def main() -> None:
    parser = argparse.ArgumentParser(description="Requeue failed reminder jobs")
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum number of jobs to evaluate in this run (default: 100)",
    )
    args = parser.parse_args()

    init_db()
    summary = requeue_failed_reminders(limit=args.limit)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
