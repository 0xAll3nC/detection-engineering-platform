.DEFAULT_GOAL := help
UV ?= uv

.PHONY: help install lint test test-all compile snapshots simulate audit secrets check clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-10s %s\n", $$1, $$2}'

install: ## Install runtime + dev dependencies and git hooks
	$(UV) sync --extra lab
	$(UV) run pre-commit install

lint: ## Run all pre-commit hooks (ruff, YAML/JSON checks, gitleaks)
	$(UV) run pre-commit run --all-files

test: ## Offline test suite with coverage
	$(UV) run pytest -m "not network" --cov --cov-report=term

test-all: ## Full suite including network-dependent validators
	$(UV) run pytest --cov --cov-report=term

compile: ## Compile Sigma rules to build/compiled/
	$(UV) run detplat compile

snapshots: ## Regenerate reviewed compiled-query snapshots (review the diff!)
	$(UV) run detplat compile --out tests/snapshots/compiled
	rm -f tests/snapshots/compiled/index.json
	git --no-pager diff --stat -- tests/snapshots/

simulate: ## Run the SIMULATED reporting pipeline
	$(UV) run detplat validate --simulate tests/fixtures/reporting/simulated_results.json

# Accepted advisories: each needs a justification in SECURITY.md
# ("Accepted dependency risks") and a tracking issue. Review on every upgrade.
AUDIT_IGNORES := --ignore-vuln PYSEC-2026-2447

audit: ## Dependency vulnerability audit
	mkdir -p build
	$(UV) export --format requirements-txt --no-hashes --no-emit-project --extra lab > build/requirements-audit.txt
	$(UV) run pip-audit --strict $(AUDIT_IGNORES) -r build/requirements-audit.txt

secrets: ## Scan full git history for secrets
	gitleaks git --redact -v .

check: lint test compile ## Everything required before opening a PR

clean: ## Remove generated artifacts
	rm -rf build .pytest_cache .ruff_cache .coverage htmlcov
