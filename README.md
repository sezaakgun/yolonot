# dippy-auto

LLM-powered supplement for [Dippy](https://github.com/lilydayton/Dippy) — analyzes commands Dippy can't decide on using an LLM (OpenAI, Ollama, or any OpenAI-compatible API).

## Problem

Dippy handles most Bash commands well, but can't analyze:
- Inline scripts: `python3 -c "import os; os.remove('file')"`
- Script files: `python3 script.py`, `bash deploy.sh`
- Complex piped commands with ambiguous intent

For these, Dippy returns "ask" and interrupts the developer.

## Solution

When Dippy says "ask", dippy-auto sends the command (and script contents if applicable) to an LLM for safety analysis. The LLM reads the actual code and decides allow/deny/ask.

## Flow

```
Bash command
  → Dippy (instant)
    → allow/deny → done
    → "ask" → LLM analyzes command + script content (~2s with OpenAI)
      → allow/deny/ask → returned to Claude Code
```

## Setup

1. Set your OpenAI API key:
   ```sh
   export OPENAI_API_KEY="sk-..."
   ```

2. Replace the Dippy hook in `~/.claude/settings.json`:
   ```json
   {
     "matcher": "Bash",
     "hooks": [
       {
         "type": "command",
         "command": "/path/to/dippy-auto/scripts/dippy-with-llm.sh",
         "timeout": 120
       }
     ]
   }
   ```

3. Restart Claude Code.

## Configuration

Environment variables:
- `OPENAI_API_KEY` — API key (required for OpenAI)
- `LLM_URL` — API endpoint (default: `https://api.openai.com/v1/chat/completions`)
- `LLM_MODEL` — model name (default: `gpt-4o-mini`)
- `LLM_TIMEOUT` — request timeout in seconds (default: `10`)

For local models (Ollama, llama.cpp):
```sh
export LLM_URL="http://localhost:11434/v1/chat/completions"
export LLM_MODEL="qwen2.5:7b"
export LLM_TIMEOUT="60"
export OPENAI_API_KEY="not-needed"
```

## Testing

```sh
# Direct test (outside Claude Code)
scripts/llm-analyze.sh 'python3 -c "print(1+1)"'
# → {"decision":"allow","confidence":1.0,"reasoning":"safe print"}

scripts/llm-analyze.sh 'python3 -c "import shutil; shutil.rmtree(\"/production\")"'
# → {"decision":"deny","confidence":1.0,"reasoning":"destructive deletion"}

# Run test suite
sh scripts/test-prompt.sh
```

## License

MIT
