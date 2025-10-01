# Root-level Makefile
# CI pipeline runs: format check → lint → (optional) typecheck → tests

.PHONY: ci install test lint fmt typecheck

PYTHON ?= python3
PIP    ?= python3 -m pip

# Install project dependencies
install:
	$(PIP) install -U pip
	$(PIP) install -r nudgepay/requirements.txt

# One-shot entry used by CI
ci: install fmt lint typecheck test

# Run tests from within the app dir so PYTHONPATH resolves local imports
test:
	cd nudgepay && PYTHONPATH=$$(pwd) TZ=UTC CI=true pytest -q

# Lint (ruff). Adjust the path if you add more packages.
lint:
	ruff check nudgepay

# Formatting check (black)
fmt:
	black --check nudgepay

# Type checking (enable when you introduce mypy/pyright)
typecheck:
	@echo "Skipping typecheck (no mypy configured)"; true
