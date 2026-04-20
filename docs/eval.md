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

## Suite format

Suites are JSONL — one test case per line. Each case has:

```json
{"cmd": "...", "expected": "allow|ask|deny", "category": "...", "notes": "..."}
```

See `evals/suites/greenfield.jsonl` and `evals/suites/brownfield.jsonl` for the shipped corpora.
