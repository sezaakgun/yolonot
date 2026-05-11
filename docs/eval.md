# Eval suite

Test LLM prompt quality across models. 176 greenfield + 70 brownfield test cases covering read-only ops, production mutations, safe dev work, sensitive commands, exfiltration, redirects, adversarial attacks, and session similarity. Each case shows LLM response time.

## Basic usage

```bash
# Run all test suites
./yolonot eval --all --model gpt-5.4-mini --runs 1 --verbose

# Compare models
./yolonot eval --suite evals/suites/greenfield.jsonl \
  --model gpt-5.4-mini --model ollama/gemma4:e4b

# Filter by category
./yolonot eval --suite evals/suites/greenfield.jsonl \
  --model gpt-5.4-mini --filter-expected ask --filter-category adversarial

# Test with Claude Code subscription
./yolonot eval --all --model claude-cli/claude-haiku-4-5-20251001 --runs 1 --verbose

# Test with OpenRouter free model
./yolonot eval --all --model openrouter/google/gemma-3-4b-it:free --runs 1 --verbose
```

## Flags

| Flag | Purpose |
|------|---------|
| `--all` | Run every suite in `evals/suites/` |
| `--suite <path>` | Run a single suite file |
| `--model <provider/model>` | Model to test. Repeatable — passing multiple runs comparison mode. |
| `--runs <n>` | Number of runs per case (useful for variance analysis). |
| `--filter-expected <allow\|ask\|deny>` | Only run cases with this expected decision. |
| `--filter-category <name>` | Only run cases with this category tag. |
| `--verbose` | Per-case timing + reasoning output. |
| `--with-hints` | Apply user classifier hints (`~/.yolonot/config.json` + `.yolonot` walk-up) when building the system prompt. Off by default. See "Reproducibility and hints" below. |
| `--metric decision\|risk` | What to grade. `decision` (default) grades the LLM's `allow`/`ask` field. `risk` grades the policy-neutral risk tier (`safe`/`low`/`moderate`/`high`/`critical`) against the case's `expected_risk` field — see "Risk-tier metric" below. |

## Reproducibility and hints

By default, eval uses the raw `SystemPrompt` const — same prompt for every
developer running the suite. Custom classifier hints from
`~/.yolonot/config.json` and `.yolonot` walk-up files are **ignored**, so
results don't drift based on per-machine configuration. This is what you
want when comparing models or measuring base prompt quality.

Pass `--with-hints` when you actually want to measure your hints:

```bash
# Did adding "kubectl get on prod-* is read-only" lower the false-ask rate?
yolonot eval --suite evals/suites/greenfield.jsonl --model gpt-5.4-mini --runs 3
yolonot eval --suite evals/suites/greenfield.jsonl --model gpt-5.4-mini --runs 3 --with-hints
```

The flag affects greenfield (risk-classification) suites only — brownfield
(session similarity) uses `ComparePrompt` and is unaffected.

## Risk-tier metric

The default metric (`--metric decision`) grades the LLM's `allow`/`ask`
output. That field already mixes prompt and policy: the prompt tells the
model "a `critical` command is always ask", so a wrong `decision` could
mean either a wrong tier or a wrong action mapping.

`--metric risk` grades the LLM's `risk` field directly — `safe`, `low`,
`moderate`, `high`, or `critical`. This is policy-neutral and downstream
of nothing: profile changes, `RiskMap` overrides, and harness differences
don't affect it. If you're tuning the prompt or hints, this is the
metric you want.

Requirements:

- Cases must have an `expected_risk` field in the suite JSONL. Cases
  without one are skipped with a count printed at suite load time.
- Brownfield suites are not graded in risk mode (they're similarity
  comparisons; no risk tier in the response).

```bash
# Compare two prompt variants on tier accuracy
yolonot eval --suite mysuite.jsonl --model gpt-5.4-mini --runs 3 --metric risk
yolonot eval --suite mysuite.jsonl --model gpt-5.4-mini --runs 3 --metric risk --with-hints
```

Today the shipped suites do not have `expected_risk` populated. Annotate
the cases you care about by hand for now, or treat this flag as ready
for custom suites you author.

## Suite format

Suites are JSONL — one test case per line. Each case has:

```json
{"cmd": "...", "expected": "allow|ask|deny", "category": "...", "notes": "..."}
```

See `evals/suites/greenfield.jsonl` and `evals/suites/brownfield.jsonl` for the shipped corpora.
