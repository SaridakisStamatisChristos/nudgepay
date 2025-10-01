.PHONY: run test lint format docker-build docker-up deploy-fly hash

run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -q

lint:
	ruff check .

format:
	black .

security-scan:
	bandit -q -r app
	pip-audit

docker-build:
	docker build -t nudgepay:latest .

docker-up:
	docker-compose up --build

deploy-fly:
	flyctl deploy

hash:
	python -c "import bcrypt, getpass; password = getpass.getpass('Password: '); print(bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode())"

migrate:
	alembic upgrade head

backup:
	bash scripts/backup.sh

ci:
	make lint
	make test
	make security-scan
	ENVIRONMENT=staging python -m nudgepay.scripts.validate_release
	ENVIRONMENT=staging DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres python -m nudgepay.scripts.schema_rehearsal --json

release-check:
	ENVIRONMENT=staging python -m nudgepay.scripts.validate_release
	ENVIRONMENT=staging DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres python -m nudgepay.scripts.schema_rehearsal --json
