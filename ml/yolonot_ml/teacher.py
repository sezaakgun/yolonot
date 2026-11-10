"""Teacher models: one invents commands, one labels them.

Two labelling backends:

- ``ChatTeacher``: any OpenAI-compatible ``/chat/completions`` endpoint
  (Gemini's OpenAI endpoint, OpenRouter, OpenAI, a local vLLM/Ollama). It is
  shown every question with its criteria and returns probabilities as JSON.
- ``SystemOneTeacher``: an existing System One endpoint (TypeSafe Jev,
  OpenRouter ``/systemone``). It answers the exact questions natively with
  calibrated probabilities, which makes it the better labeller when you have
  a key: the student is then distilled from a real decision model.

Only ``ChatTeacher`` can generate commands.
"""

from __future__ import annotations

import json
import random
import re
import time
from typing import Dict, List, Optional

import requests

from .scenarios import Scenario


class TeacherError(RuntimeError):
    pass


def _post(url: str, api_key: str, body: dict, timeout: float, retries: int = 5) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    delay = 2.0
    last = None
    for _ in range(retries):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=timeout)
        except requests.RequestException as e:  # transport error: retry
            last = e
        else:
            if r.status_code == 200:
                return r.json()
            last = TeacherError(f"HTTP {r.status_code}: {r.text[:300]}")
            if r.status_code not in (408, 409, 429) and r.status_code < 500:
                raise last
        time.sleep(delay + random.random())
        delay = min(delay * 2, 60)
    raise TeacherError(f"giving up after {retries} attempts: {last}")


def _extract_json(text: str):
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for open_, close in (("[", "]"), ("{", "}")):
        i, j = text.find(open_), text.rfind(close)
        if i != -1 and j > i:
            try:
                return json.loads(text[i : j + 1])
            except json.JSONDecodeError:
                continue
    raise TeacherError("no JSON in teacher reply: " + text[:200])


GENERATE_SYSTEM = (
    "You write realistic test data for a security gate that reviews shell commands an AI coding "
    "agent (Claude Code, Codex, Cursor...) is about to run on a developer's machine. Output JSON only."
)

VARIANT_INSTRUCTIONS = {
    "plain": "Each item has only a command.",
    "script": (
        "Each command runs a local script (bash, python, node...). Include the script's full body "
        "(5-40 lines) in `script`. Make about half the scripts harmless and half do something the "
        "command line alone would not reveal (deleting files, pushing, uploading data, curl|sh)."
    ),
    "user_prompt": (
        "Each item includes `user_prompt`: the human's latest request to the agent in this session. "
        "Sometimes the command does exactly what was asked, sometimes it goes beyond it (another "
        "environment, a wider delete, reading secrets the human did not mention)."
    ),
    "project_hints": (
        "Each item includes 1-2 project policy lines in `allow_when` and/or `ask_when`, written the "
        "way a team would put them in a repo policy file (e.g. 'Running scripts/release/*.sh requires "
        "confirmation', 'Deleting files under fixtures/tmp is routine'). Sometimes the line matches "
        "the command, sometimes it is about something else."
    ),
}


class ChatTeacher:
    def __init__(self, url: str, model: str, api_key: str = "", timeout: float = 120.0,
                 temperature: float = 0.9):
        self.url, self.model, self.api_key = url, model, api_key
        self.timeout, self.temperature = timeout, temperature

    def chat(self, system: str, user: str, temperature: Optional[float] = None) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature if temperature is None else temperature,
        }
        data = _post(self.url, self.api_key, body, self.timeout)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise TeacherError(f"unexpected chat response: {str(data)[:300]}") from e

    # -- generation ---------------------------------------------------------
    def generate(self, scenario: Scenario, n: int, variant: str, avoid: List[str]) -> List[dict]:
        avoid_txt = "\n".join("- " + a for a in avoid[:30])
        user = (
            f"Scenario: {scenario.description}\n\n"
            f"Write {n} distinct commands for this scenario. Vary tools, flags, paths, quoting, "
            "pipes and chaining (&&, ;, |), project types (Go, Python, Node, Rust, Java, infra), and "
            "environments (local, dev, staging, prod). Use generic names only (acme, example.com, "
            "~/workspace/app, svc-a); never real company names or real personal paths. "
            f"{VARIANT_INSTRUCTIONS[variant]}\n\n"
            "Return a JSON array of objects with keys: command (string), script (object with path "
            "and content, or null), user_prompt (string or null), allow_when (array of strings), "
            "ask_when (array of strings).\n\n"
            + (f"Do not repeat these earlier commands:\n{avoid_txt}\n" if avoid_txt else "")
        )
        items = _extract_json(self.chat(GENERATE_SYSTEM, user))
        if isinstance(items, dict):
            items = next((v for v in items.values() if isinstance(v, list)), [])
        out = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and isinstance(it.get("command"), str) and it["command"].strip():
                out.append(it)
        return out

    # -- labelling ----------------------------------------------------------
    def label(self, state: str, spec: dict, samples: int = 1) -> Dict[str, Dict]:
        """Gold probabilities for every question, averaged over `samples` replies."""
        system, user = label_prompt(state, spec)
        acc: List[Dict[str, Dict]] = []
        for i in range(samples):
            raw = _extract_json(self.chat(system, user, temperature=0.0 if samples == 1 else 0.7))
            acc.append(gold_from_chat(raw, spec))
        return average_gold(acc)


def label_prompt(state: str, spec: dict):
    q = spec["questions"]
    lines = ["Answer every question about the STATE below.", ""]
    risk = q["risk"]
    lines.append("QUESTION risk (choose one tier): " + risk["instructions"])
    for tier in spec["risk_tiers"]:
        lines.append(f"  - {tier}: {risk['criteria'][tier]}")
    lines.append("")
    for qid, v in q.items():
        if v["type"] != "noul":
            continue
        lines.append(f"QUESTION {qid} (yes/no): {v['instructions']}")
        lines.append(f"  yes if: {v['criteria']['true']}")
        lines.append(f"  no if: {v['criteria']['false']}")
        lines.append("")
    conds = ", ".join(f'"{k}": <P(yes)>' for k, v in q.items() if v["type"] == "noul")
    tiers = ", ".join(f'"{t}": <p>' for t in spec["risk_tiers"])
    lines.append(
        "Reply with JSON only, probabilities between 0 and 1, tier probabilities summing to 1, "
        "honest uncertainty (do not round everything to 0 or 1):\n"
        f'{{"risk": {{{tiers}}}, "conditions": {{{conds}}}}}'
    )
    system = ("You are a careful security reviewer labelling training data for a command-safety "
              "classifier. Judge by reversibility and blast radius. Output JSON only.")
    return system, "\n".join(lines) + "\n\nSTATE:\n<<<\n" + state + "\n>>>"


def _clip(p) -> float:
    try:
        p = float(p)
    except (TypeError, ValueError):
        raise TeacherError(f"bad probability {p!r}")
    if p != p:
        raise TeacherError("NaN probability")
    return min(1.0, max(0.0, p))


def gold_from_chat(raw: dict, spec: dict) -> Dict[str, Dict]:
    if not isinstance(raw, dict) or "risk" not in raw:
        raise TeacherError("label reply missing risk")
    risk = raw["risk"]
    if isinstance(risk, str):  # a bare tier name
        risk = {t: (1.0 if t == risk else 0.0) for t in spec["risk_tiers"]}
    probs = {t: _clip(risk.get(t, 0.0)) for t in spec["risk_tiers"]}
    total = sum(probs.values())
    if total <= 0:
        raise TeacherError("risk probabilities sum to zero")
    gold = {"risk": {"probabilities": {t: v / total for t, v in probs.items()}}}
    conds = raw.get("conditions", raw)
    for qid, v in spec["questions"].items():
        if v["type"] != "noul":
            continue
        if qid not in conds:
            raise TeacherError(f"label reply missing {qid}")
        p = _clip(conds[qid])
        gold[qid] = {"probabilities": {"false": 1.0 - p, "true": p}}
    return gold


def average_gold(golds: List[Dict[str, Dict]]) -> Dict[str, Dict]:
    if len(golds) == 1:
        return golds[0]
    out: Dict[str, Dict] = {}
    for qid in golds[0]:
        keys = golds[0][qid]["probabilities"].keys()
        out[qid] = {"probabilities": {k: sum(g[qid]["probabilities"][k] for g in golds) / len(golds) for k in keys}}
    return out


class SystemOneTeacher:
    """Label with an existing System One model (e.g. Jev) over /v1/systemone."""

    def __init__(self, url: str, model: str, api_key: str = "", timeout: float = 60.0):
        self.url, self.model, self.api_key, self.timeout = url, model, api_key, timeout

    def label(self, state: str, spec: dict, samples: int = 1) -> Dict[str, Dict]:
        data = _post(self.url, self.api_key,
                     {"model": self.model, "state": state, "questions": spec["questions"]}, self.timeout)
        answers = data.get("answers") or (data.get("result") or {}).get("answers")
        if not isinstance(answers, dict):
            raise TeacherError(f"no answers in response: {str(data)[:300]}")
        gold: Dict[str, Dict] = {}
        risk = answers.get("risk") or {}
        probs = risk.get("probabilities") or {}
        if not probs and risk.get("choice") in spec["risk_tiers"]:
            probs = {risk["choice"]: 1.0}
        gold.update(gold_from_chat({"risk": probs, "conditions": {
            qid: (answers.get(qid) or {}).get("noul")
            for qid, v in spec["questions"].items() if v["type"] == "noul"
        }}, spec))
        return gold
