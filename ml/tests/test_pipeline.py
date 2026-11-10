import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from yolonot_ml import scenarios as S  # noqa: E402
from yolonot_ml.generate import case_from_item, plan  # noqa: E402
from yolonot_ml.leakage import LeakageFilter, eval_commands  # noqa: E402
from yolonot_ml.spec import Case, condition_ids, decision_from_answers, load_spec, render_state  # noqa: E402
from yolonot_ml.teacher import gold_from_chat, label_prompt  # noqa: E402

SPEC = load_spec()


def test_render_matches_go_example():
    ex = SPEC["example"]
    assert render_state(Case(command=ex["command"]), SPEC) == ex["state"]


def test_spec_has_ten_questions():
    assert SPEC["questions"]["risk"]["type"] == "choice"
    assert len(condition_ids(SPEC)) == 9
    assert set(SPEC["questions"]["risk"]["criteria"]) == set(SPEC["risk_tiers"])


def test_decision_mirrors_call_decision():
    none = {c: 0.1 for c in condition_ids(SPEC)}
    assert decision_from_answers("low", none, SPEC) == "allow"
    assert decision_from_answers("high", none, SPEC) == "ask"
    assert decision_from_answers("critical", none, SPEC) == "ask"
    assert decision_from_answers("safe", dict(none, exfil=0.5), SPEC) == "ask"


def test_gold_from_chat_normalises():
    raw = {"risk": {"safe": 2, "low": 2}, "conditions": {c: 0.2 for c in condition_ids(SPEC)}}
    gold = gold_from_chat(raw, SPEC)
    assert abs(gold["risk"]["probabilities"]["safe"] - 0.5) < 1e-9
    assert gold["exfil"]["probabilities"] == {"false": 0.8, "true": 0.2}


def test_label_prompt_contains_state_and_all_questions():
    _, user = label_prompt("Command: ls", SPEC)
    assert "Command: ls" in user
    for q in SPEC["questions"]:
        assert q in user


def test_leakage_filter_drops_eval_commands():
    ref = eval_commands()
    assert len(ref) > 200
    f = LeakageFilter(ref)
    assert f.leaks(ref[0])
    assert f.leaks("  " + ref[0].upper() + " ")
    assert not f.leaks("echo totally-unrelated-synthetic-command 42")


def test_case_variants_render():
    rng = random.Random(1)
    item = {"command": "bash scripts/x.sh", "script": {"path": "scripts/x.sh", "content": "echo hi\n"},
            "user_prompt": "run the script", "allow_when": ["a"], "ask_when": ["b"]}
    for _ in range(50):
        st = render_state(case_from_item(item, rng), SPEC)
        assert st.startswith("Command: bash scripts/x.sh")
        assert "Analyze: is this safe to execute?" in st
        assert "- b\n" in st


def test_plan_covers_every_scenario():
    jobs = plan(3000, random.Random(0), 15)
    assert {s.id for s, _ in jobs} == {s.id for s in S.SCENARIOS}
