# Automated validation script for pdpa-audit-mcp (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==> 1. Running Ruff linter..." -ForegroundColor Cyan
python -m uv run ruff check .

Write-Host "==> 2. Checking Ruff formatting..." -ForegroundColor Cyan
python -m uv run ruff format --check .

Write-Host "==> 3. Running pytest with -W error::ResourceWarning..." -ForegroundColor Cyan
python -m uv run pytest -W error::ResourceWarning

Write-Host "==> 4. Building distribution package with uv..." -ForegroundColor Cyan
python -m uv build

Write-Host "==> 5. Running dependency security audit with pip-audit..." -ForegroundColor Cyan
$venvPython = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $env:PIPAPI_PYTHON_LOCATION = (Resolve-Path $venvPython).Path
}
python -m uv run pip-audit

Write-Host "==> All checks passed successfully!" -ForegroundColor Green
