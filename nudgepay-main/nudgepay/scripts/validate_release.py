"""Validate deployment settings prior to promotion."""

from __future__ import annotations

import json
import sys

from nudgepay.app.config import SettingsValidationError, get_settings


def main() -> int:
    settings = get_settings()
    try:
        result = settings.ensure_valid(strict=True)
    except SettingsValidationError as exc:
        print(f"Configuration validation failed: {exc}", file=sys.stderr)
        return 1

    output = {
        "environment": settings.environment,
        "warnings": list(result.warnings),
        "errors": list(result.errors),
        "database_url": settings.database_url,
        "session_https_only": settings.session_https_only,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
