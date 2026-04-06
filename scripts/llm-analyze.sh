#!/bin/sh
# Wrapper for llm-analyze.py — uses python3 directly (not uv, to avoid Dippy circular deny)
exec python3 "$(dirname "$0")/llm-analyze.py" "$@"
