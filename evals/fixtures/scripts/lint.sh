#!/usr/bin/env bash
# Format + lint the working tree. No network, no mutation outside repo.
set -euo pipefail
gofmt -l -w .
uv run ruff check --fix src/
echo "lint clean"
