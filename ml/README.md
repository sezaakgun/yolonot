# Local System One judge (experimental)

Train a local typed decision model that answers the same questions yolonot's
typed judge sends to TypeSafe Jev, then run it on your own machine in place of
a chat LLM:

```json
"judges": ["fast_allow", "yolonot-s1"]
```

The model is [Laya](https://github.com/NandhaKishorM/laya) (ModernBERT-large,
421M, Apache-2.0) fine-tuned on synthetic, teacher-labelled commands. Laya
serves the System One wire protocol (`POST /v1/systemone`), so yolonot needs no
code changes: it is just another catalog entry with `"protocol": "systemone"`.

## Contract

`spec/yolonot_systemone.json` holds the questions (one risk-tier choice and
nine yes/no ask conditions), the default hint sections and a rendered example
state. It is generated from `internal/yolonot/decision.go`, and
`TestMLSpecInSync` fails when the Go side changes without it:

```bash
YOLONOT_UPDATE_ML_SPEC=1 go test ./internal/yolonot -run TestMLSpecInSync
```

A changed question means the model has to be retrained: it was trained on the
old wording.

## Pipeline

| Step | Where | What |
|------|-------|------|
| Generate | `yolonot_ml/generate.py` | A teacher chat model writes commands for ~45 scenarios (`scenarios.py`) covering every tier, every ask condition and look-alikes. Some get attached scripts, a user prompt, project `Allow when` / `Ask when` lines, the sandbox-bypass marker or an auto-detected project line, the same variations the hook produces. |
| Leakage filter | `yolonot_ml/leakage.py` | Drops any command that equals or nearly copies an `evals/suites` command, so the suites stay a fair test set. |
| Render | `yolonot_ml/spec.py` | Builds the exact state string the hook sends (tested against the Go-rendered example). |
| Label | `yolonot_ml/teacher.py` | A chat teacher answers every question with probabilities, or an existing System One model (Jev via OpenRouter) labels natively. |
| Train / eval | `notebooks/yolonot_laya_colab.ipynb` | `laya-train` from `laya-typed-decisions`, then `yolonot eval` on greenfield and script-attach against the zero-shot base (and Jev, with a key). |

Rows are Laya's `{state, questions, gold}` format plus a `meta` block.
Training data is generated on demand and never committed (`data/` is ignored).

### Colab

Open `notebooks/yolonot_laya_colab.ipynb` in Colab (File → Open notebook →
GitHub), pick a GPU runtime, add a `GEMINI_API_KEY` secret (any
OpenAI-compatible chat endpoint works; set `TEACHER_URL` / `TEACHER_MODEL`),
and run all cells. Start with `TARGET_ROWS = 300` as a smoke run.

### Without Colab

```bash
cd ml
pip install -r requirements.txt
python -m yolonot_ml.generate --out data/train.jsonl --target 3000 \
  --gen-url https://generativelanguage.googleapis.com/v1beta/openai/chat/completions \
  --gen-model gemini-2.5-flash --gen-key-env GEMINI_API_KEY
laya-train --data data/train.jsonl --base convaiinnovations/laya-typed-decisions \
  --out data/yolonot-s1 --max-len 2048 --head-max-len 512 --dry-run
```

Tests: `python -m pytest ml/tests`.

## Run it locally

```bash
pip install "laya[serve]"
tar xzf yolonot-s1.tgz -C ~/models
LAYA_HOST=127.0.0.1 LAYA_PORT=8009 \
LAYA_EXTRA_MODELS='{"yolonot-s1": "'$HOME'/models/yolonot-s1"}' \
LAYA_MODELS=yolonot-s1 laya-serve
```

Keep it on loopback: yolonot only accepts plain `http://` for loopback hosts.
Add the model to `~/.yolonot/config.json` and put it in the chain:

```json
"models": {
  "yolonot-s1": {"protocol": "systemone", "url": "http://127.0.0.1:8009/v1/systemone", "model": "yolonot-s1", "timeout": 5}
},
"judges": ["fast_allow", "yolonot-s1"]
```

Then `yolonot models test yolonot-s1` and `yolonot check "<command>"`.

## What changes without a chat model

The typed judge never says `deny` (rules and the risk map do), it cannot be
the escalation model, and Explain, `suggest` smart mode, session similarity
and `rules review` need a chat model. Without one in the catalog they are
skipped. See [docs/models.md](../docs/models.md).

## Ship criteria

Before recommending it to anyone: 100% dangerous catch on greenfield and
script-attach (no `ask`/`deny` case allowed), decision accuracy at or above
Jev's published 92.0% on greenfield, and p50 latency on Apple Silicon well
under a chat model's.
