// yolonot — OpenCode plugin shim
//
// OpenCode's plugin protocol (tool.execute.before / tool.execute.after) is
// TypeScript-native and does not match the stdin/stdout JSON contract that
// yolonot's hook uses. This file bridges the two: it shells out to
// `yolonot hook`, feeds it a Claude-compatible PreToolUse / PostToolUse
// payload on stdin, and translates the response back into the Error-throw
// convention that OpenCode uses for blocking.
//
// This file is embedded into the Go binary via //go:embed and written to
// ~/.config/opencode/plugin/yolonot.ts by `yolonot install --harness opencode`.
// Do not import from @opencode-ai/plugin here — keeping it import-free means
// Bun can run it without the plugin type package being present in the user's
// .opencode/node_modules.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any

const YOLONOT_BIN = "__YOLONOT_BIN__" // rewritten at install time

async function askYolonot(
  event: "PreToolUse" | "PostToolUse",
  sessionID: string,
  command: string,
  cwd: string,
  toolResponse: Any,
): Promise<{ decision: string; reason: string }> {
  const payload = {
    hook_event_name: event,
    tool_name: "Bash",
    session_id: sessionID,
    cwd,
    tool_input: { command },
    ...(toolResponse !== undefined ? { tool_response: toolResponse } : {}),
  }

  const proc = Bun.spawn([YOLONOT_BIN, "hook"], {
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, YOLONOT_HARNESS: "opencode" },
  })
  proc.stdin.write(JSON.stringify(payload))
  await proc.stdin.end()

  const [out, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    proc.exited,
  ])
  if (exitCode !== 0 || !out.trim()) {
    return { decision: "allow", reason: "" }
  }
  try {
    const parsed = JSON.parse(out)
    const h = parsed.hookSpecificOutput ?? {}
    return {
      decision: h.permissionDecision ?? "allow",
      reason: h.permissionDecisionReason ?? "",
    }
  } catch {
    return { decision: "allow", reason: "" }
  }
}

// OpenCode 1.4.3 expects a named export annotated as Plugin. Default
// exports and PluginModule-shaped wrappers are not recognised by the
// loader. Keep the name stable so users can see it in `opencode --plugins`.
export const YolonotPlugin = async (_ctx: Any) => ({
  "tool.execute.before": async (input: Any, output: Any) => {
    if (input.tool !== "bash") return
    const command = output?.args?.command ?? ""
    if (!command) return
    const cwd = output?.args?.cwd ?? process.cwd()
    const { decision, reason } = await askYolonot(
      "PreToolUse",
      input.sessionID ?? "",
      command,
      cwd,
      undefined,
    )
    // OpenCode's plugin API has no "ask" primitive: only throw-to-block
    // or return-to-allow. Risk map now expresses policy via allow/deny/
    // passthrough; "ask" should not appear unless user-forced. Treat:
    //   - deny → throw (hard block)
    //   - ask  → return (defer to host's own prompt engine)
    //   - allow / "" / missing → return
    if (decision === "deny") {
      throw new Error(`yolonot: ${reason || decision}`)
    }
  },

  // tool.execute.after signature (opencode 1.4.3):
  //   input:  {tool, sessionID, callID, args}
  //   output: {title, output, metadata}
  // The command lives on input.args; the stdout/stderr/title lives on output.
  "tool.execute.after": async (input: Any, output: Any) => {
    if (input.tool !== "bash") return
    const command = input?.args?.command ?? ""
    if (!command) return
    const cwd = input?.args?.cwd ?? process.cwd()
    await askYolonot(
      "PostToolUse",
      input.sessionID ?? "",
      command,
      cwd,
      { output: output?.output ?? "", title: output?.title ?? "" },
    )
  },
})
