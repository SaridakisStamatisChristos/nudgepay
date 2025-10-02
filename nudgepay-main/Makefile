# Root-level Makefile that delegates into the application directory.
# This keeps developer ergonomics aligned with the CI workflow defined in
# `.github/workflows/ci.yml` which runs `make ci` from inside `nudgepay/`.

.PHONY: ci install lint fmt fmt-fix test typecheck help

APP_DIR ?= nudgepay

help:
	@echo "Targets mirror those inside $(APP_DIR)/Makefile"
	@echo "  make install   → install development dependencies"
	@echo "  make lint      → run ruff lint checks"
	@echo "  make fmt       → run formatting check"
	@echo "  make fmt-fix   → auto-format source"
	@echo "  make test      → execute pytest suite"
	@echo "  make ci        → run the full CI pipeline"

install:
	$(MAKE) -C $(APP_DIR) install-dev

lint:
	$(MAKE) -C $(APP_DIR) lint

fmt:
	$(MAKE) -C $(APP_DIR) format

fmt-fix:
	$(MAKE) -C $(APP_DIR) format-fix

test:
	$(MAKE) -C $(APP_DIR) test

ci:
	$(MAKE) -C $(APP_DIR) ci

typecheck:
	$(MAKE) -C $(APP_DIR) typecheck
