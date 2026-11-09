#!/usr/bin/env bash
# Automated validation script for pdpa-audit-mcp (Linux / macOS)
set -euo pipefail

echo "==> 1. Running Ruff linter..."
uv run ruff check .

echo "==> 2. Checking Ruff formatting..."
uv run ruff format --check .

echo "==> 3. Running pytest with -W error::ResourceWarning..."
uv run pytest -W error::ResourceWarning

echo "==> 4. Building distribution package with uv..."
uv build

echo "==> 5. Running dependency security audit with pip-audit..."
if [ -f ".venv/bin/python" ]; then
    export PIPAPI_PYTHON_LOCATION="$(pwd)/.venv/bin/python"
fi
uv run pip-audit

echo "==> All checks passed successfully!"
