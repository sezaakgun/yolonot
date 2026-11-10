"""Build the synthetic training set: generate commands, render states, label.

    python -m yolonot_ml.generate \
        --out data/train.jsonl --target 6000 \
        --gen-url https://generativelanguage.googleapis.com/v1beta/openai/chat/completions \
        --gen-model gemini-2.5-flash --gen-key-env GEMINI_API_KEY

Labelling uses the same chat model unless ``--label-protocol systemone`` points
at a System One endpoint (Jev via OpenRouter: ``--label-url
https://openrouter.ai/api/v1/systemone --label-model typesafe/jev-1.13
--label-key-env OPENROUTER_API_KEY``).

Output rows are Laya's ``{state, questions, gold}`` training format plus a
``meta`` block (scenario, command, teacher decision) for analysis. The run
is resumable: commands already in ``--out`` are skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List

from . import scenarios as S
from .leakage import LeakageFilter, eval_commands
from .spec import Case, Hints, Script, condition_ids, decision_from_answers, load_spec, render_state
from .teacher import ChatTeacher, SystemOneTeacher, TeacherError

VARIANT_WEIGHTS = {
    "plain": 1.0 - S.SCRIPT_SHARE - S.USER_PROMPT_SHARE - S.PROJECT_HINT_SHARE,
    "script": S.SCRIPT_SHARE,
    "user_prompt": S.USER_PROMPT_SHARE,
    "project_hints": S.PROJECT_HINT_SHARE,
}


def dedupe_key(cmd: str) -> str:
    return " ".join(cmd.split())


def case_from_item(item: dict, rng: random.Random) -> Case:
    scripts, withheld = [], []
    sc = item.get("script")
    if isinstance(sc, dict) and isinstance(sc.get("content"), str) and sc.get("path"):
        if rng.random() < S.WITHHELD_SHARE / max(S.SCRIPT_SHARE, 1e-9):
            withheld.append(str(sc["path"]))
        else:
            scripts.append(Script(path=str(sc["path"]), content=sc["content"][:8000]))
    return Case(
        command=item["command"].strip(),
        scripts=scripts,
        withheld=withheld,
        user_prompt=(item.get("user_prompt") or "").strip(),
        active_project=rng.choice(S.ACTIVE_PROJECTS) if rng.random() < S.ACTIVE_PROJECT_SHARE else "",
        bypass_sandbox=rng.random() < S.BYPASS_SANDBOX_SHARE,
        use_default_hints=rng.random() >= S.NO_DEFAULT_HINTS_SHARE,
        hints=Hints(
            allow_when=[s for s in item.get("allow_when") or [] if isinstance(s, str)],
            ask_when=[s for s in item.get("ask_when") or [] if isinstance(s, str)],
        ),
    )


def plan(target: int, rng: random.Random, batch: int) -> List[tuple]:
    """(scenario, variant) batches whose sizes follow scenario weights."""
    total_w = sum(s.weight for s in S.SCENARIOS)
    jobs = []
    for s in S.SCENARIOS:
        n = max(batch, round(target * s.weight / total_w))
        for _ in range(max(1, n // batch)):
            variant = rng.choices(list(VARIANT_WEIGHTS), weights=list(VARIANT_WEIGHTS.values()))[0]
            jobs.append((s, variant))
    rng.shuffle(jobs)
    return jobs


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True)
    p.add_argument("--target", type=int, default=6000, help="approximate number of labelled rows")
    p.add_argument("--batch", type=int, default=15, help="commands per generation call")
    p.add_argument("--gen-url", required=True)
    p.add_argument("--gen-model", required=True)
    p.add_argument("--gen-key-env", default="")
    p.add_argument("--label-protocol", choices=["chat", "systemone"], default="chat")
    p.add_argument("--label-url", default="")
    p.add_argument("--label-model", default="")
    p.add_argument("--label-key-env", default="")
    p.add_argument("--label-samples", type=int, default=1, help="chat labels averaged per state")
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)

    spec = load_spec()
    rng = random.Random(args.seed)
    gen = ChatTeacher(args.gen_url, args.gen_model, os.environ.get(args.gen_key_env, "") if args.gen_key_env else "")
    if args.label_protocol == "systemone":
        labeler = SystemOneTeacher(args.label_url, args.label_model,
                                   os.environ.get(args.label_key_env, "") if args.label_key_env else "")
    elif args.label_url:
        labeler = ChatTeacher(args.label_url, args.label_model or args.gen_model,
                              os.environ.get(args.label_key_env, "") if args.label_key_env else "")
    else:
        labeler = gen

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    if out_path.exists():
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    seen.add(dedupe_key(json.loads(line)["meta"]["command"]))
    print(f"resuming with {len(seen)} existing rows", file=sys.stderr)

    leak = LeakageFilter(eval_commands())
    lock = threading.Lock()
    stats: Dict[str, int] = {"generated": 0, "dup": 0, "leak": 0, "label_err": 0, "written": len(seen)}
    recent: Dict[str, List[str]] = {}

    def run_job(job):
        scenario, variant = job
        if stats["written"] >= args.target:
            return
        try:
            items = gen.generate(scenario, args.batch, variant, recent.get(scenario.id, []))
        except TeacherError as e:
            print(f"[gen] {scenario.id}: {e}", file=sys.stderr)
            return
        for item in items:
            with lock:
                stats["generated"] += 1
                key = dedupe_key(item["command"])
                if key in seen:
                    stats["dup"] += 1
                    continue
                if leak.leaks(item["command"]):
                    stats["leak"] += 1
                    continue
                seen.add(key)
                recent.setdefault(scenario.id, []).append(item["command"])
                case_rng = random.Random(rng.random())
            case = case_from_item(item, case_rng)
            state = render_state(case, spec)
            try:
                gold = labeler.label(state, spec, samples=args.label_samples)
            except TeacherError as e:
                with lock:
                    stats["label_err"] += 1
                print(f"[label] {e}", file=sys.stderr)
                continue
            risk = max(gold["risk"]["probabilities"].items(), key=lambda kv: kv[1])[0]
            conds = {q: gold[q]["probabilities"]["true"] for q in condition_ids(spec)}
            row = {
                "state": state,
                "questions": spec["questions"],
                "gold": gold,
                "meta": {
                    "scenario": scenario.id,
                    "variant": variant,
                    "command": case.command,
                    "teacher_risk": risk,
                    "teacher_decision": decision_from_answers(risk, conds, spec),
                },
            }
            with lock:
                with open(out_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
                stats["written"] += 1

    jobs = plan(int(args.target * 1.3), rng, args.batch)  # head-room for dups/leaks/errors
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(run_job, j) for j in jobs]
        for i, fut in enumerate(as_completed(futures), 1):
            fut.result()
            if i % 10 == 0:
                print(f"{i}/{len(jobs)} batches {stats}", file=sys.stderr)
    print(json.dumps(stats), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
