"""Run release validation with local-friendly defaults."""
from __future__ import annotations

from . import ci_env
from . import validate_release


def main() -> int:
    ci_env.apply_ci_environment_defaults()
    return validate_release.main()


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
