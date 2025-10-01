import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent

for path in (REPO_ROOT, PROJECT_ROOT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


def pytest_configure() -> None:
    """Ensure cached settings and secret fallbacks do not leak between tests."""

    from app import config as app_config
    from app import secret_manager

    app_config.reset_settings_cache()
    secret_manager.resolve_managed_secret.cache_clear()
    secret_manager._FALLBACK_STORE.clear()


@pytest.fixture(autouse=True)
def _reset_state():
    from app import config as app_config
    from app import secret_manager

    app_config.reset_settings_cache()
    secret_manager.resolve_managed_secret.cache_clear()
    secret_manager._FALLBACK_STORE.clear()
    yield
    app_config.reset_settings_cache()
    secret_manager.resolve_managed_secret.cache_clear()
    secret_manager._FALLBACK_STORE.clear()
