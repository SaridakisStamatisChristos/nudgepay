# Use a safer shell
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

.PHONY: run test lint format format-fix security-scan docker-build docker-up deploy-fly hash migrate backup ci release-check install-dev

PYTHON ?= python3
PIP    ?= python3 -m pip

# ---- Database config (override in CI) ----
PGHOST ?= localhost
PGPORT ?= 5432
PGDB   ?= postgres
PGUSER ?= postgres
PGPASS ?= postgres
# If DATABASE_URL is not provided by the environment, build one from the vars above
DATABASE_URL ?= postgresql://$(PGUSER):$(PGPASS)@$(PGHOST):$(PGPORT)/$(PGDB)

# ---- Dev helpers ----
install-dev:
	$(PIP) install -U pip
	$(PIP) install -r requirements.txt
	$(PIP) install ruff black bandit pip-audit pytest alembic uvicorn bcrypt

# ---- App ----
run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	PYTHONPATH=$$(pwd) TZ=UTC CI=true pytest -q

lint:
	ruff check .

# CI-friendly (fails if formatting is off)
format:
	black --check .

# Local convenience to auto-fix formatting
format-fix:
	black .

security-scan:
	bandit -q -r app
	pip-audit

docker-build:
	docker build -t nudgepay:latest .

docker-up:
	docker compose up --build

deploy-fly:
	flyctl deploy

hash:
	python -c "import bcrypt, getpass; password = getpass.getpass('Password: '); print(bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode())"

migrate:
	alembic upgrade head

backup:
	bash scripts/backup.sh

# ---- CI entrypoints ----
ci:
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) security-scan
	ENVIRONMENT=staging python -m nudgepay.scripts.validate_release
	ENVIRONMENT=staging DATABASE_URL='$(DATABASE_URL)' python -m nudgepay.scripts.schema_rehearsal --json

release-check:
	ENVIRONMENT=staging python -m nudgepay.scripts.validate_release
	ENVIRONMENT=staging DATABASE_URL='$(DATABASE_URL)' python -m nudgepay.scripts.schema_rehearsal --json

