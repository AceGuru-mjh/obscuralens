# ObscuraLens developer recipes.
# Run `just` with no arguments to list everything below.

# List the available recipes.
default:
    @just --list

# Install the package in editable mode with dev extras.
install:
    python -m pip install -e ".[dev]"

# Run the unit tests (excludes integration).
test:
    pytest -m "not integration" --no-color

# Run the live integration script (hits real network services).
integration:
    python test_core.py

# Lint with ruff.
lint:
    ruff check .

# Auto-fix lint issues with ruff.
fmt:
    ruff check --fix .

# Launch the interactive console.
run:
    python -m obscuralens

# Start the web UI.
serve:
    python -m obscuralens serve

# Start the terminal UI.
tui:
    python -m obscuralens tui

# Start the MCP stdio server.
mcp:
    python -m obscuralens mcp

# Build sdist and wheel.
build:
    python -m build

# Remove caches and build artefacts.
clean:
    -rm -rf build dist *.egg-info .pytest_cache .ruff_cache
    -find . -type d -name __pycache__ -prune -exec rm -rf {} +
