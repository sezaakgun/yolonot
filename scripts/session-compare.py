#!/usr/bin/env python3
"""Compare a new command against previously approved commands in the session.

Usage: session-compare.py "new command" /path/to/session.approved

Returns JSON: {"decision":"allow|ask","reasoning":"...","compared_to":"..."}
"""

import json
import os
import subprocess
import sys

LLM_URL = os.environ.get("LLM_URL", "https://api.openai.com/v1/chat/completions")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT = os.environ.get("LLM_TIMEOUT", "10")
LLM_API_KEY = os.environ.get("OPENAI_API_KEY", "")

SYSTEM_PROMPT = """You compare a new command against previously approved commands.
Output ONLY JSON: {"decision":"allow|ask","reasoning":"one line","compared_to":"the approved command it's similar to, or empty"}

Rules:
- allow: The new command has the SAME intent, risk level, and target as an approved command. Only superficial differences (IDs, timestamps, filenames of same type).
- ask: The new command is materially different — different action, different target, different risk level, or different scope.

Examples:
- Approved: "kubectl delete job vector-123 -n dev" → New: "kubectl delete job vector-456 -n dev" → ALLOW (same action, same namespace, different job name)
- Approved: "kubectl delete job vector-123 -n dev" → New: "kubectl delete deployment api -n dev" → ASK (different resource type)
- Approved: "kubectl delete job vector-123 -n dev" → New: "kubectl delete job vector-123 -n production" → ASK (different namespace)
- Approved: "uv run python test.py" → New: "uv run python deploy.py" → ASK (completely different script)
- Approved: "uv run python test.py" → New: "uv run python test.py --verbose" → ALLOW (same script, extra flag)
- Approved: "rm -rf /tmp/cache-abc" → New: "rm -rf /tmp/cache-def" → ALLOW (same temp dir pattern)
- Approved: "rm -rf /tmp/cache-abc" → New: "rm -rf /home/user/data" → ASK (different location entirely)

Be strict. When in doubt, ask."""


def main():
    if len(sys.argv) < 3:
        print('{"decision":"ask","reasoning":"missing arguments"}')
        return

    new_command = sys.argv[1]
    session_file = sys.argv[2]

    # Read approved commands
    if not os.path.isfile(session_file):
        print('{"decision":"ask","reasoning":"no approved commands"}')
        return

    with open(session_file) as f:
        approved = [line.strip() for line in f if line.strip()]

    if not approved:
        print('{"decision":"ask","reasoning":"no approved commands"}')
        return

    # Check exact match first
    if new_command in approved:
        print(json.dumps({
            "decision": "allow",
            "reasoning": "exact match",
            "compared_to": new_command,
        }))
        return

    # Build prompt
    approved_list = "\n".join(f"- {cmd}" for cmd in approved[-10:])  # last 10
    user_prompt = f"""Previously approved commands this session:
{approved_list}

New command: {new_command}

Is this new command similar enough to auto-allow?"""

    # Call LLM
    body = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "max_tokens": 256,
        "temperature": 0,
    })

    cmd = ["curl", "-s", "-m", LLM_TIMEOUT, LLM_URL,
           "-H", "Content-Type: application/json"]
    if LLM_API_KEY:
        cmd += ["-H", f"Authorization: Bearer {LLM_API_KEY}"]
    cmd += ["-d", body]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0 or not result.stdout:
            print('{"decision":"ask","reasoning":"LLM unavailable"}')
            return
        response = json.loads(result.stdout)
    except Exception:
        print('{"decision":"ask","reasoning":"LLM error"}')
        return

    # Parse response
    import re
    msg = response["choices"][0]["message"]
    text = msg.get("content", "") or msg.get("reasoning_content", "")
    text = re.sub(r"```json?\s*", "", text)
    text = re.sub(r"```", "", text)

    idx = text.find('"decision"')
    if idx < 0:
        print('{"decision":"ask","reasoning":"no decision in response"}')
        return

    start = text.rfind("{", 0, idx)
    if start < 0:
        print('{"decision":"ask","reasoning":"parse error"}')
        return

    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    result = json.loads(text[start:i + 1])
                    print(json.dumps(result))
                    return
                except json.JSONDecodeError:
                    break

    print('{"decision":"ask","reasoning":"parse error"}')


if __name__ == "__main__":
    main()
