# Contributing to yolonot

Thanks for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/sezaakgun/yolonot.git
cd yolonot
go build -o yolonot .
go test ./...
```

Requires Go 1.25+.

## Making Changes

1. Fork the repo and create a branch from `main`
2. Write your code
3. Add or update tests as needed
4. Run `go test ./...` and make sure everything passes
5. Run `go vet ./...` for static analysis
6. Open a pull request

## Project Structure

```
main.go         CLI entry point
hook.go         Hook handler pipeline
llm.go          LLM client + prompts + response parsing
rules.go        Rule loading + glob matching + chain detection
session.go      Session files (approved/asked/denied)
config.go       Config + settings.json + install/uninstall
eval.go         LLM evaluation runner
log.go          Decision logging (JSONL)
main_test.go    Unit tests
evals/suites/   LLM eval test cases (JSONL)
```

## Running Evals

To test LLM prompt quality across models:

```bash
./yolonot eval --all --model gpt-5.4-mini --runs 1 --verbose
```

## Adding Eval Cases

Add JSONL lines to `evals/suites/greenfield.jsonl` (command classification) or `evals/suites/brownfield.jsonl` (session similarity). Follow the existing format and include meaningful IDs, categories, and notes.

## Reporting Bugs

Open an issue with:
- What you expected vs what happened
- The command that triggered the issue
- Output from `yolonot log` if relevant

## Code Style

- Follow standard Go conventions (`gofmt`)
- Keep functions focused and small
- Add tests for new features and bug fixes
- No unnecessary abstractions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
