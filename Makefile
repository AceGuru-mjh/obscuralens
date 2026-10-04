# ObscuraLens developer Makefile.
# Thin wrappers around the project's standard commands. Run `make help`.

.DEFAULT_GOAL := help

PYTHON ?= python
PIP ?= $(PYTHON) -m pip

.PHONY: help install test integration bench bench-quick lint fmt run start serve tui mcp build clean

help: ## Show this help
	@echo "ObscuraLens targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package in editable mode with dev extras
	$(PIP) install -e ".[dev]"

test: ## Run the unit tests (excludes integration)
	$(PYTHON) -m pytest -m "not integration" --no-color

integration: ## Run the live integration script (hits real network services)
	$(PYTHON) scripts/smoke_live.py

bench: ## Run the offline benchmark suite (full mode, ~2 min)
	$(PYTHON) -m benchmarks.run

bench-quick: ## Run the benchmark suite in CI-quick mode (seconds)
	$(PYTHON) -m benchmarks.run --quick

lint: ## Lint with ruff
	$(PYTHON) -m ruff check .

fmt: ## Auto-fix lint issues with ruff
	$(PYTHON) -m ruff check --fix .

run: ## Launch the interactive console
	$(PYTHON) -m obscuralens

start: ## One-command web UI (creates .venv, installs deps, opens browser)
	./start.sh

serve: ## Start the web UI
	$(PYTHON) -m obscuralens serve

tui: ## Start the terminal UI
	$(PYTHON) -m obscuralens tui

mcp: ## Start the MCP stdio server
	$(PYTHON) -m obscuralens mcp

build: ## Build sdist and wheel
	$(PYTHON) -m build

clean: ## Remove caches and build artefacts
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
