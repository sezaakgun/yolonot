#!/usr/bin/env python3
"""LLM script analyzer — supplements Dippy for complex commands.

Reads command/script content, asks local LLM if safe.

Usage:
    llm-analyze.py "python3 -c 'print(1)'"
    echo "python3 script.py" | llm-analyze.py

Returns JSON: {"decision":"allow|deny|ask","confidence":0.9,"reasoning":"..."}
"""

import json
import os
import re
import subprocess
import sys

LLM_URL = os.environ.get("LLM_URL", "https://api.openai.com/v1/chat/completions")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = os.environ.get("LLM_TIMEOUT", "10")
LLM_API_KEY = os.environ.get("OPENAI_API_KEY", "")

SYSTEM_PROMPT = """You are a command safety classifier. Evaluate in this EXACT order:
Output ONLY JSON: {"decision":"allow|deny|ask","confidence":0.0-1.0,"reasoning":"one line"}

STEP 1 — Is this a READ-ONLY operation? If yes → ALLOW regardless of target.
Read-only means: get, describe, list, logs, status, cat, head, tail, grep, find, ls, tree, wc, history.
Examples that are ALWAYS ALLOWED even on production:
  kubectl get pods --namespace production → ALLOW (read-only)
  helm list --namespace production → ALLOW (read-only)
  helm status my-release --namespace production → ALLOW (read-only)
  aws ec2 describe-instances --profile prod → ALLOW (read-only)
  aws s3 ls s3://prod-bucket → ALLOW (read-only)
  cat /etc/hosts → ALLOW (read-only)

STEP 2 — Is this a MUTATION on PRODUCTION? If yes → DENY.
Mutations: delete, apply, patch, create, update, terminate, rm, drop, truncate, install, upgrade, rollback.
Production indicators: prod, production, live, main, master in context/namespace/profile/branch.
Examples:
  kubectl delete pod X --context prod → DENY
  aws ec2 terminate-instances --profile prod → DENY
  helm install X --namespace production → DENY
  git push --force origin main → DENY

STEP 3 — Is this safe routine development work? If yes → ALLOW.
  Build/test: go test, make, npm test, pytest, cargo test
  Package mgmt: go mod, npm install, pip install, uv run
  Git: status, diff, log, commit, push to feature branches
  Local cleanup: rm -rf /tmp/*, __pycache__, node_modules, build/
  Docker: compose up/down/restart (local dev)
  Linting: golangci-lint, prettier, black, ruff
  Simple scripts: print, echo, hello world

STEP 4 — Is this sensitive but possibly needed? If yes → ASK.
  Reading .env, .pem, .key, .ssh files
  Network requests to external URLs
  Writing files outside project directory
  Database migrations
  Git history modification (rebase, amend, reset --hard)
  Mutations on staging/QA (not prod but impactful)
  Running unfamiliar binaries

STEP 5 — If none of the above matched → ASK.
When in doubt, ask. False deny is worse than false ask."""


def get_command():
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:])
    return sys.stdin.read().strip()


def read_script_file(command):
    """If command references a script file, read its contents."""
    match = re.search(r'[\s]([^\s]+\.(py|sh|js|rb|ts))(\s|$)', " " + command)
    if not match:
        return ""
    path = match.group(1)
    if not os.path.isfile(path):
        return ""
    try:
        with open(path) as f:
            lines = f.readlines()[:100]
        return "".join(lines)
    except Exception:
        return ""


def build_prompt(command):
    prompt = f"Command: {command}"

    script = read_script_file(command)
    if script:
        prompt += f"\n\nScript file contents:\n{script}"

    # Extract inline script from -c "..."
    inline = re.search(r'-c\s+["\'](.+?)["\']', command)
    if inline:
        prompt += f"\n\nInline script:\n{inline.group(1)}"

    prompt += "\n\nAnalyze: is this safe to execute?"
    return prompt


def call_llm(prompt):
    body = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 4096,
        "temperature": 0,
    })

    cmd = ["curl", "-s", "-m", LLM_TIMEOUT, LLM_URL,
           "-H", "Content-Type: application/json"]
    if LLM_API_KEY:
        cmd += ["-H", f"Authorization: Bearer {LLM_API_KEY}"]
    cmd += ["-d", body]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 or not result.stdout:
        return None
    return json.loads(result.stdout)


def parse_response(response):
    msg = response["choices"][0]["message"]
    text = msg.get("content", "") or msg.get("reasoning_content", "")

    # Strip code fences
    text = re.sub(r"```json?\s*", "", text)
    text = re.sub(r"```", "", text)

    # Find JSON with decision key — walk braces for proper nesting
    idx = text.find('"decision"')
    if idx < 0:
        return None
    start = text.rfind("{", 0, idx)
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i+1])
                except json.JSONDecodeError:
                    return None
    return None


def main():
    command = get_command()
    if not command:
        print('{"decision":"ask","reasoning":"no command provided"}')
        return

    prompt = build_prompt(command)

    try:
        response = call_llm(prompt)
    except Exception:
        print('{"decision":"ask","reasoning":"LLM unavailable"}')
        sys.exit(1)

    if not response:
        print('{"decision":"ask","reasoning":"LLM unavailable"}')
        sys.exit(1)

    try:
        decision = parse_response(response)
    except Exception:
        print('{"decision":"ask","reasoning":"parse error"}')
        return

    if decision:
        print(json.dumps(decision))
    else:
        print('{"decision":"ask","reasoning":"no decision in LLM response"}')


if __name__ == "__main__":
    main()
