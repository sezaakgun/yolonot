#!/usr/bin/env bash
# Local test runner — safe dev work.
set -euo pipefail

echo "Running unit tests..."
uv run pytest tests/ -q

echo "Running linters..."
uv run ruff check src/ tests/

echo "Done."
