# Manual desktop checklist

Desktop apps cannot be driven by `go test -tags e2e`. Run this list before a
release, against the commit you are about to ship:

```bash
scripts/signoff --dry-run claude-desktop    # guided run, nothing posted
scripts/signoff claude-desktop              # same, then posts manual/claude-desktop
```

The script builds the candidate, creates a workspace with these project
rules, and installs the candidate into the app's hooks:

```
allow-cmd touch *ALLOW*
deny-cmd touch *DENY*
ask-cmd touch *ASK*
```

For each row it copies the prompt to the clipboard, tells you what to do,
waits for Enter, then checks the marker file and `~/.yolonot/decisions.jsonl`
itself. It asks y/n only for things it cannot see. When it ends, also on
Ctrl+C, it reinstalls the yolonot on your PATH into that app. Installing the
candidate changes your real host settings for the duration of the run.

Row format, read by the script: **Do** steps are separated by `Then:`; the
marker is deleted between steps. **Check** items are separated by `;`:
`marker`, `no marker`, `log <layer>:<decision>`, `no log <layer>:<decision>`,
`see: <question>`.

## Claude Desktop

Before: add the chat model's key in **Local → gear** (shell exports do not
reach Desktop) so Explain works. The script opens a local Code session on
the workspace (`claude://code/new?folder=<workspace>`); use that session for
every row.

| # | Marker | Do | Check |
|---|--------|----|-------|
| 1 | ALLOW-CD | Switch the session to the default mode (shift+tab; not Plan, not Auto) and check the mode label. Then: Send the prompt. | marker; log rule:allow; no log rule:ask |
| 2 | DENY-CD | Send the prompt. | no marker; log rule:deny |
| 3 | ASK-CD-ONCE | Send the prompt and choose Allow once. Then: Send the prompt again and choose Deny in the new dialog. | no marker; log human:allow; log human:deny |
| 4 | ASK-CD-SESSION | Send the prompt and choose Allow this session. Then: Send the prompt again. | marker; log session:allow |
| 5 | ASK-CD-REJECT | Send the prompt and choose Deny. Then: Send the prompt again. | no marker; log human:deny; log session_deny:deny |
| 6 | ASK-CD-EXPLAIN | Send the prompt, choose Explain, read it, then choose Deny. | no marker; log human:deny; see: An explanation was shown, not an HTTP or credential error? |
| 7 | ASK-CD-ESC | Send the prompt and press Esc on the dialog. Then: Send the prompt again and choose Deny. | no marker; no log session_deny:deny; log human:deny |
| 8 | ALLOW-CD-AUTO | Switch the session to Auto mode (shift+tab) and check the mode label shows Auto. Then: Send the prompt. | marker; log rule:allow |
| 9 | DENY-CD-AUTO | Stay in Auto mode and send the prompt. | no marker; log rule:deny |
| 10 | ASK-CD-AUTO | Stay in Auto mode, send the prompt and choose Deny. | no marker; log human:deny |

## Codex Desktop

Before: the script opens a new Codex thread on the workspace
(`codex://new?path=<workspace>`); use that thread for every row. Trust the
yolonot hooks in `/hooks`.

Codex hooks cannot ask the user, so yolonot draws no dialog here: an ask is
handed to Codex's own approval request. These rows check that yolonot
approves that request for allowed commands, blocks denied ones, and never
approves an ask by itself. Every prompt asks for escalated permissions, so
Codex sends an approval request on every row; a write inside the workspace
would not need one.

| # | Marker | Do | Check |
|---|--------|----|-------|
| 1 | ALLOW-CX | Choose **Ask for approval** in the picker under the message box ("Approve for me" and "Full access" approve requests without you). Then: Send the prompt. | marker; log rule:allow; see: The command ran without an approval request in the chat? |
| 2 | DENY-CX | Send the prompt. | no marker; log rule:deny |
| 3 | ASK-CX-APPROVE | Send the prompt and approve the request in the chat. | marker; log rule:ask; see: The chat waited for your approval before running? |
| 4 | ASK-CX-REJECT | Send the prompt and reject the request in the chat. | no marker; log rule:ask; no log human:allow |
| 5 | ASK-CX-REPEAT | Send the prompt and approve. Then: Send the prompt again and approve. | marker; see: The repeat asked for approval again? |

## Cursor IDE

Before: the script points the hooks at a wrapper that turns on native ask
(`YOLONOT_CURSOR_NATIVE_ASK=1`) and opens Cursor on the workspace. If Cursor
was already running, quit it and run `open -a Cursor <workspace>` so it
reloads `~/.cursor/hooks.json`.

| # | Marker | Do | Check |
|---|--------|----|-------|
| 1 | ALLOW-CI | Send the prompt. | marker; log rule:allow |
| 2 | DENY-CI | Send the prompt. | no marker; log rule:deny |
| 3 | ASK-CI-APPROVE | Send the prompt and choose Run in the approval prompt. | marker; log rule:ask; see: Cursor showed a Run/Skip prompt before running? |
| 4 | ASK-CI-REJECT | Send the prompt and choose Skip. | no marker; log rule:ask; no log human:allow |

## After the run

Update the dated host rows in [docs/harnesses.md](../docs/harnesses.md#verification-scope).
