# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please do **not** report security vulnerabilities through public GitHub issues.

Use [GitHub Private Vulnerability Reporting](https://github.com/sezaakgun/yolonot/security/advisories/new) to report suspected vulnerabilities privately. Include:

- Affected version (`yolonot --version`) and harness (`claude`, `codex`, `opencode`, `antigravity`, `cursor`)
- Minimal reproduction steps and the exact command or hook payload involved
- Expected vs. actual decision (`allow`, `ask`, `deny`, `passthrough`)

## Security Model & Scope

yolonot gates shell tool calls exposed by supported coding harnesses. It does not replace OS-level process sandboxing, mediate non-shell file/MCP tools, or act as a privilege boundary against processes already running as your user.

See [docs/security.md](docs/security.md) for the full trust model, script attachment boundary, sandbox-bypass isolation, and failure policy documentation.
