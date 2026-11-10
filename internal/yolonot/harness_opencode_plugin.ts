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
// ~/.config/opencode/plugins/yolonot.ts by `yolonot install --harness opencode`.
// Only use runtime builtins: neither SDK version is required on disk.

import { spawnSync } from "node:child_process"
import { resolve } from "node:path"

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Any = any

const YOLONOT_BIN = "__YOLONOT_BIN__" // rewritten at install time

async function runYolonotProcess(args: string[], inputJSON: string, nativeAsk: boolean): Promise<{ stdout: string; exitCode: number }> {
  const env = {
    ...process.env,
    YOLONOT_HARNESS: "opencode",
    YOLONOT_OPENCODE_API: nativeAsk ? "2" : "1",
  }
  if (typeof globalThis.Bun !== "undefined" && typeof globalThis.Bun.spawn === "function") {
    const proc = globalThis.Bun.spawn([YOLONOT_BIN, ...args], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
      env,
    })
    proc.stdin.write(inputJSON)
    await proc.stdin.end()
    const [stdout, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      proc.exited,
      // Drain diagnostics concurrently so a full stderr pipe cannot stall
      // a hook that is trying to return its verdict.
      new Response(proc.stderr).text(),
    ])
    return { stdout, exitCode }
  }
  const res = spawnSync(YOLONOT_BIN, args, { input: inputJSON, encoding: "utf8", env, timeout: 60000 })
  return { stdout: res.stdout ?? "", exitCode: res.error ? 1 : (res.status ?? 1) }
}

async function resolveYolonot(
  sessionID: string,
  command: string,
  cwd: string,
  verdict: "allow-once" | "allow-session" | "deny",
  nativeAsk = false,
  toolUseID = "",
): Promise<void> {
  if (!sessionID || !command) return
  const payload = {
    session_id: sessionID,
    tool_use_id: toolUseID || "oc-ask",
    cwd,
    command,
    verdict,
    completed: true,
  }
  await runYolonotProcess(["mod", "resolve"], JSON.stringify(payload), nativeAsk)
}

function mapReplyToVerdict(reply: Any): "allow-once" | "allow-session" | "deny" | "" {
  if (reply === "always" || reply === "allow-always" || reply === "allow-session") return "allow-session"
  if (reply === "once" || reply === "allow-once") return "allow-once"
  if (reply === "reject" || reply === "deny") return "deny"
  return ""
}

async function askYolonot(
  event: "PreToolUse" | "PostToolUse",
  sessionID: string,
  command: string,
  cwd: string,
  toolResponse: Any,
  nativeAsk = false,
  toolUseID = "",
): Promise<{ decision: string; reason: string }> {
  const payload = {
    hook_event_name: event,
    tool_name: "Bash",
    session_id: sessionID,
    cwd,
    tool_input: { command },
    ...(toolUseID ? { tool_use_id: toolUseID } : {}),
    ...(toolResponse !== undefined ? { tool_response: toolResponse } : {}),
  }

  const { stdout: out, exitCode } = await runYolonotProcess(["hook"], JSON.stringify(payload), nativeAsk)
  // A failed process or malformed response blocks. Successful empty output
  // is the hook's intentional passthrough contract (pause, disabled, an
  // empty chain, or a configured passthrough action), not a process failure.
  if (exitCode !== 0) {
    return { decision: "deny", reason: `yolonot hook exited ${exitCode} — failing closed` }
  }
  if (!out.trim()) {
    return { decision: "", reason: "" }
  }
  try {
    const parsed = JSON.parse(out)
    const h = parsed?.hookSpecificOutput
    if (!h || typeof h !== "object" || Array.isArray(h)) {
      throw new Error("missing hookSpecificOutput")
    }
    const decision = h.permissionDecision
    const reason = h.permissionDecisionReason ?? ""
    if (!["allow", "ask", "deny"].includes(decision) || typeof reason !== "string") {
      throw new Error("invalid hook decision")
    }
    return {
      decision,
      reason,
    }
  } catch (e) {
    return { decision: "deny", reason: `yolonot hook returned unparseable output — failing closed` }
  }
}

// OpenCode 1.4.3 expects a named export annotated as Plugin. Default
// exports and PluginModule-shaped wrappers are not recognised by the
// loader. Keep the name stable so users can see it in `opencode --plugins`.
export const YolonotPlugin = async (_ctx: Any) => {
  const pendingAsks = new Map<string, { sessionID: string; command: string; cwd: string; callID: string }>()
  const askKey = (sessionID: string, callID: string) => `${sessionID}:${callID}`
  return {
    "tool.execute.before": async (input: Any, output: Any) => {
      if (input.tool !== "bash") return
      const command = output?.args?.command ?? ""
      if (!command) return
      const directory = _ctx.directory ?? process.cwd()
      const cwd = resolve(directory, output?.args?.workdir ?? output?.args?.cwd ?? directory)
      const sessionID = input.sessionID ?? ""
      const callID = input.callID ?? ""
      const { decision, reason } = await askYolonot(
        "PreToolUse",
        sessionID,
        command,
        cwd,
        undefined,
        false,
        callID,
      )
      // OpenCode's plugin API has no "ask" primitive: only throw-to-block
      // or return-to-allow. Risk map now expresses policy via allow/deny/
      // passthrough; "ask" should not appear unless user-forced. Treat:
      //   - deny → throw (hard block)
      //   - ask  → return (defer to host's own prompt engine)
      //   - allow → return (includes successful empty hook output)
      if (decision === "deny") {
        throw new Error(`yolonot: ${reason || decision}`)
      }
      if (decision === "ask") {
        pendingAsks.set(askKey(sessionID, callID), { sessionID, command, cwd, callID })
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
      const directory = _ctx.directory ?? process.cwd()
      const cwd = resolve(directory, input?.args?.workdir ?? input?.args?.cwd ?? directory)
      const sessionID = input.sessionID ?? ""
      const callID = input.callID ?? ""
      pendingAsks.delete(askKey(sessionID, callID))
      await askYolonot(
        "PostToolUse",
        sessionID,
        command,
        cwd,
        { output: output?.output ?? "", title: output?.title ?? "" },
        false,
        callID,
      )
    },

    event: async ({ event }: Any) => {
      if (event?.type !== "permission.replied") return
      const props = event.properties ?? {}
      const sessionID = props.sessionID ?? ""
      const callID = props.callID ?? props.tool?.callID ?? ""
      const verdict = mapReplyToVerdict(props.reply ?? props.response)
      if (!verdict) return
      const k = askKey(sessionID, callID)
      const info = pendingAsks.get(k)
      pendingAsks.delete(k)
      const command = info?.command ?? props.command ?? props.metadata?.command ?? ""
      const directory = _ctx.directory ?? process.cwd()
      const cwd = info?.cwd ?? resolve(directory, props.cwd ?? directory)
      await resolveYolonot(sessionID || info?.sessionID || "", command, cwd, verdict, false, callID || info?.callID || "")
    },
  }
}

// OpenCode V2 uses a default {id, setup} definition and domain APIs rather
// than V1's named factory. No SDK dependency is needed for this definition.
export default {
  id: "yolonot",
  // Current V1 loaders recognize {id, server}; V2 recognizes {id, setup}.
  server: YolonotPlugin,
  async setup(ctx: Any) {
    const pending = new Map<string, { decision: string; reason: string; command: string; cwd: string; sessionID: string; id: string }>()
    const key = (sessionID: string, id: string) => JSON.stringify([sessionID, id])
    const directory = ctx.location.directory

    await ctx.permission.hook("evaluate", async (event: Any) => {
      if (event.action !== "shell" || event.source?.type !== "tool") return
      const verdict = pending.get(key(event.sessionID, event.source.id))
      if (!verdict || event.effect === "deny") return
      event.effect = verdict.decision
      if (verdict.reason) event.message = `yolonot: ${verdict.reason}`
    })

    if (typeof ctx.event?.subscribe === "function") {
      await ctx.event.subscribe(async (ev: Any) => {
        const event = ev?.event ?? ev
        if (event?.type !== "permission.replied") return
        const props = event.properties ?? event
        const sessionID = props.sessionID ?? ""
        const callID = props.callID ?? props.source?.id ?? ""
        const verdict = mapReplyToVerdict(props.reply ?? props.response)
        if (!verdict) return
        const info = pending.get(key(sessionID, callID))
        const command = info?.command ?? props.command ?? ""
        const cwd = info?.cwd ?? resolve(directory, props.cwd ?? directory)
        await resolveYolonot(sessionID || info?.sessionID || "", command, cwd, verdict, true, callID || info?.id || "")
      })
    }

    // Wrapping execute inspects the final input after all execute.before
    // middleware has run. A later argument rewrite cannot reuse a verdict
    // from an earlier before-hook for the same call ID.
    await ctx.tool.transform((editor: Any) => {
      for (const tool of editor.list()) {
        if (tool.name !== "shell") continue
        editor.update(tool.id, (current: Any) => {
          const execute = current.execute
          current.execute = async (input: Any, context: Any) => {
            const command = input.command
            const cwd = resolve(directory, input.workdir ?? directory)
            const callKey = key(context.sessionID, context.id)
            const verdict = await askYolonot("PreToolUse", context.sessionID, command, cwd, undefined, true, context.id ?? "")
            if (verdict.decision === "deny") throw new Error(`yolonot: ${verdict.reason || "deny"}`)
            // Empty output is passthrough, not an instruction to override
            // OpenCode's own permission policy.
            if (verdict.decision !== "") pending.set(callKey, { ...verdict, command, cwd, sessionID: context.sessionID, id: context.id ?? "" })
            try {
              const result = await execute(input, context)
              await askYolonot("PostToolUse", context.sessionID, command, cwd, result, true, context.id ?? "")
              return result
            } finally {
              pending.delete(callKey)
            }
          }
        })
      }
    })
    return () => pending.clear()
  },
}
