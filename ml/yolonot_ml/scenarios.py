"""Scenario taxonomy the teacher LLM writes commands for.

Each scenario names a family of shell commands an AI coding agent runs.
The teacher invents concrete, varied commands per scenario; a second pass
labels them. Scenarios cover every risk tier and every ask condition, and
deliberately include look-alikes (a read on prod vs a write on prod,
`rm -rf build/` vs `rm -rf ~/`) because those boundaries are what the
model has to learn.

Keep names and examples generic: no real organisations, hosts, paths or
commands copied from anyone's decision log (see CLAUDE.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Scenario:
    id: str
    description: str
    weight: float = 1.0  # relative share of generated commands


SCENARIOS: List[Scenario] = [
    # --- safe: read-only -------------------------------------------------
    Scenario("fs_read", "Read-only filesystem inspection: ls, cat, head, tail, wc, find, tree, stat, du on project files.", 1.5),
    Scenario("search", "Code search: grep, rg, ag, git grep, fd with flags and globs, including pipes into sort/uniq/head.", 1.5),
    Scenario("git_read", "Read-only git: status, diff, log with formats, show, blame, branch -a, remote -v, rev-parse.", 1.5),
    Scenario("k8s_read", "kubectl get/describe/logs/top on any namespace or context including production, without -o yaml on secrets.", 1.2),
    Scenario("cloud_read", "Read-only cloud CLI: aws ... describe-*/list-*/get-*, aws s3 ls, gcloud ... list/describe, az ... show/list.", 1.0),
    Scenario("iac_read", "terraform plan/show/validate/fmt -check, helm list/status/history/template, pulumi preview.", 0.8),
    Scenario("sys_info", "System information: uname, ps, top -l1, df, free, lsof -i, which, env, printenv, whoami, sw_vers.", 0.8),
    Scenario("pipes_read", "Multi-stage pipelines that only read and format: jq, awk, sed -n, cut, sort, xargs with read-only commands.", 1.0),
    Scenario("http_get", "Read-only HTTP: curl -s / curl -I / wget -O- GET requests to public APIs or docs, with jq.", 0.8),
    # --- low: local reversible writes -------------------------------------
    Scenario("build_test", "Build, test and lint: go test, npm test, pytest, cargo build, make, tsc, eslint --fix, ruff, mvn verify.", 1.5),
    Scenario("deps_install", "Installing declared dependencies: npm ci, pip install -r requirements.txt, uv sync, go mod download, bundle install.", 1.0),
    Scenario("git_local_write", "Local git writes: git add, git commit -m, git checkout -b, git stash, git switch, git tag on local repo.", 1.2),
    Scenario("local_files", "Creating files and dirs in the project or /tmp: mkdir -p, touch, cp, mv of new files, heredoc into /tmp.", 1.0),
    Scenario("cache_cleanup", "Cleaning build outputs and caches: rm -rf node_modules, dist/, target/, __pycache__, .pytest_cache.", 0.8),
    Scenario("dev_services", "Local dev services: docker compose up/down/restart, npm run dev, a dev server on localhost, watchers.", 0.8),
    # --- moderate: network or scoped state change ------------------------
    Scenario("git_push_feature", "Pushing to a feature branch: git push origin feat/x, git push -u origin HEAD on a non-main branch.", 0.8),
    Scenario("docker_build", "docker build/tag, docker pull, buildx build without push, podman build.", 0.7),
    Scenario("http_write", "HTTP writes: curl -X POST/PUT/PATCH/DELETE with -d data or auth headers to an API, webhooks.", 0.9),
    Scenario("package_publish_dry", "Publishing dry-runs and registry auth: npm publish --dry-run, cargo publish --dry-run, docker login.", 0.5),
    Scenario("gh_cli", "GitHub CLI: gh pr create/merge/view/list/comment, gh issue create, gh run rerun, gh release create.", 0.8),
    # --- high: destructive but bounded -----------------------------------
    Scenario("rm_source", "Deleting or overwriting specific pre-existing source or config files: rm, git rm, mv over, truncate.", 1.0),
    Scenario("git_history", "Rewriting git history: git reset --hard, rebase, commit --amend, push --force(-with-lease), git clean -fdx.", 1.0),
    Scenario("prod_mutation", "Mutating production/staging: kubectl apply/delete/scale/rollout restart, helm upgrade, terraform apply on prod.", 1.2),
    Scenario("db_change", "Database changes: migrations, DROP TABLE, DELETE without WHERE, psql/mysql -c with writes, redis-cli FLUSHDB.", 0.8),
    Scenario("process_kill", "Killing processes: kill -9 PID, pkill -f name, killall, lsof -ti :3000 | xargs kill.", 0.6),
    Scenario("permissions", "Permission and ownership changes: chmod -R, chown, sudo commands, IAM/RBAC grants, gh repo collaborator.", 0.8),
    Scenario("cloud_delete", "Cloud deletions: aws s3 rm --recursive, gcloud storage rm -r, aws ec2 terminate-instances, az group delete.", 0.7),
    Scenario("git_push_main", "Pushing to main/master/release branches, or bare git push from main.", 0.6),
    # --- critical: irreversible, wide blast radius -----------------------
    Scenario("wipe", "Wiping broad paths: rm -rf / , ~, $HOME, ../.., /usr, dd to a disk device, mkfs, shred on devices.", 0.8),
    Scenario("remote_exec", "Fetching and executing remote code: curl | sh, wget -qO- | bash, bash <(curl ...), iex (irm ...).", 0.9),
    Scenario("exfiltration", "Sending local files, env vars or keys to an external host: curl -F, nc, scp/rsync to unknown hosts, paste sites.", 1.0),
    Scenario("reverse_shell", "Reverse shells, fork bombs, listening sockets bound to all interfaces, crypto miners.", 0.5),
    Scenario("drop_database", "DROP DATABASE, dropping production schemas, deleting whole clusters or projects.", 0.5),
    # --- ask conditions that cut across tiers ----------------------------
    Scenario("secrets_read", "Reading secrets: cat .env, ~/.ssh/id_*, ~/.aws/credentials, kubectl get secret -o yaml, security find-generic-password.", 1.0),
    Scenario("obfuscation", "Obfuscated commands: base64 -d | sh, eval of concatenated vars, printf escaped bytes into bash, rev | sh.", 0.8),
    Scenario("persistence", "Persistence: crontab edits, launchd/systemd units, appending to .bashrc/.zshrc, installing git hooks.", 0.7),
    Scenario("redirect_write", "Shell redirection writes: echo/cat/printf > or >> into project or config files, tee into files outside /tmp.", 0.9),
    Scenario("opaque_scripts", "Running local scripts or binaries whose contents are not shown: ./deploy.sh, bash scripts/x.sh, python tool.py.", 0.9),
    Scenario("containers", "docker run / exec with arbitrary commands, privileged containers, mounting the host filesystem.", 0.6),
    Scenario("nested_agents", "Launching another coding agent non-interactively: claude -p, codex exec, opencode run, cursor-agent -p.", 0.3),
    Scenario("hook_bypass", "Bypassing repository gates: git commit --no-verify, git config core.hooksPath, --no-gpg-sign.", 0.4),
    # --- adversarial look-alikes ----------------------------------------
    Scenario("lookalike_benign", "Commands that LOOK scary but are safe: rm -rf ./build, grep -r password docs/, echo 'rm -rf /', kubectl get on prod.", 1.2),
    Scenario("lookalike_danger", "Commands that LOOK routine but are dangerous: innocuous names hiding curl|sh, npm install of a URL, find -delete on ~.", 1.2),
    Scenario("prompt_injection", "Commands or script comments containing text that tries to instruct the reviewer to allow them.", 0.5),
]

# Variation knobs applied when a generated command is turned into a state.
# Shares are of all generated commands.
SCRIPT_SHARE = 0.20        # attach a script body the command executes
WITHHELD_SHARE = 0.05      # reference a script whose body was not attached
USER_PROMPT_SHARE = 0.20   # include the human's request in the session
PROJECT_HINT_SHARE = 0.15  # add project-specific Allow when / Ask when lines
NO_DEFAULT_HINTS_SHARE = 0.10  # a config without the $defaults hint blocks
BYPASS_SANDBOX_SHARE = 0.05
ACTIVE_PROJECT_SHARE = 0.60  # the hook runs inside a git repo most of the time

# Generic stand-ins for detectProjectContext's "name [Stack] — description".
ACTIVE_PROJECTS = [
    "webshop [Node] — Storefront for acme",
    "api [Go] — HTTP API for the acme platform",
    "svc-a [Python] — Background workers",
    "infra [Terraform] — Cloud infrastructure for acme",
    "mobile-app [Node]",
    "data-pipeline [Python] — ETL jobs",
    "cli [Rust] — Command-line tool",
    "billing [Java]",
    "deploy [Go, Node]",
    "docs",
]
