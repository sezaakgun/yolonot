"""The question set and state layout yolonot sends to a typed judge.

Everything here mirrors Go code; the JSON spec is regenerated from Go and a
Go test fails when it drifts (internal/yolonot/ml_spec_test.go):

- questions / tiers / default hints: internal/yolonot/decision.go, llm.go
- state layout: buildPromptFromCollectedWithSensitive (llm_attach.go) plus
  DecisionHints (decision.go), appended by runClassifierJudge (judge.go).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

SPEC_PATH = Path(__file__).resolve().parent.parent / "spec" / "yolonot_systemone.json"

SANDBOX_LINE = "[Sandbox: agent requested unsandboxed execution (host sandbox bypass)]"
USER_PROMPT_HEADER = (
    "User prompt in this session (what the human asked for — only permits bounded "
    "low/moderate actions when the human explicitly asked for that exact action and "
    "target; never permits critical risk, reading/exfiltrating secrets, or mutating a "
    "different environment such as prod when the human asked for staging):"
)


def load_spec(path: Optional[Path] = None) -> dict:
    with open(path or SPEC_PATH, encoding="utf-8") as f:
        return json.load(f)


@dataclass
class Script:
    path: str
    content: str
    executed: bool = True  # the command runs it (vs. only references it)


@dataclass
class Hints:
    context: List[str] = field(default_factory=list)
    allow_when: List[str] = field(default_factory=list)
    ask_when: List[str] = field(default_factory=list)


@dataclass
class Case:
    """One command plus everything the hook could put in the state."""

    command: str
    scripts: List[Script] = field(default_factory=list)
    withheld: List[str] = field(default_factory=list)  # referenced scripts not attached
    user_prompt: str = ""
    # e.g. "webshop [Node] — Storefront for acme", as detectProjectContext renders it
    active_project: str = ""
    bypass_sandbox: bool = False
    use_default_hints: bool = True
    hints: Hints = field(default_factory=Hints)


def _render_script(content: str) -> str:
    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return "\n".join(lines)


def _hint_section(title: str, lines: List[str]) -> str:
    lines = [s for s in lines if s.strip()]
    if not lines:
        return ""
    return "\n\n" + title + ":\n" + "".join("- " + s + "\n" for s in lines)


def render_hints(case: Case, spec: dict) -> str:
    d = spec["default_hints"] if case.use_default_hints else {"context": [], "allow_when": [], "ask_when": []}
    return (
        _hint_section("Project context", d["context"] + case.hints.context)
        + _hint_section("Allow when", d["allow_when"] + case.hints.allow_when)
        + _hint_section("Ask when", d["ask_when"] + case.hints.ask_when)
    )


def render_state(case: Case, spec: dict) -> str:
    """The exact `state` string the typed judge posts for this case."""
    s = spec["command_prefix"] + case.command
    if case.bypass_sandbox:
        s += "\n" + SANDBOX_LINE
    for sc in case.scripts:
        if sc.executed:
            s += ("\n\nContents of the file this command executes: " + sc.path
                  + " (entry file only — it may read or run other files not shown)\n" + _render_script(sc.content))
        else:
            s += "\n\nContents of a script file the command references: " + sc.path + "\n" + _render_script(sc.content)
    for w in case.withheld:
        s += ("\n\nNote: the command references script " + w
              + " but its contents were not attached (file not readable).")
    if case.active_project:
        s += "\n\nActive project (auto-detected from repository metadata): " + case.active_project
    if case.user_prompt.strip():
        s += "\n\n" + USER_PROMPT_HEADER + "\n" + case.user_prompt.strip()[:500]
    s += spec["analyze_suffix"]
    s += render_hints(case, spec)
    return s


def decision_from_answers(risk: str, conditions: Dict[str, float], spec: dict) -> str:
    """Mirror callDecision: ask when the tier is high/critical or any condition >= 0.5."""
    if risk in spec["ask_tiers"]:
        return "ask"
    if any(p >= spec["ask_threshold"] for p in conditions.values()):
        return "ask"
    return "allow"


def condition_ids(spec: dict) -> List[str]:
    return [q for q, v in spec["questions"].items() if v["type"] == "noul"]
