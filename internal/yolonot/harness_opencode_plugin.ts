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
const MAX_PENDING_ENTRIES = 256

function setBounded<K, V>(map: Map<K, V>, k: K, v: V): void {
  if (!map.has(k) && map.size >= MAX_PENDING_ENTRIES) {
    const oldest = map.keys().next().value
    if (oldest !== undefined) map.delete(oldest)
  }
  map.set(k, v)
}

function extractBypassSandbox(rawInput: Any): boolean {
  if (!rawInput || typeof rawInput !== "object") return false
  return Boolean(
    rawInput.dangerouslyDisableSandbox === true ||
      rawInput.BypassSandbox === true ||
      rawInput.bypass_sandbox === true ||
      rawInput.requestSandboxBypass === true ||
      rawInput.with_escalated_permissions === true ||
      rawInput.sandbox === false ||
      rawInput.sandbox_permissions === "require_escalated",
  )
}

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
  bypassSandbox = false,
): Promise<void> {
  if (!sessionID || !command) return
  const payload = {
    session_id: sessionID,
    tool_use_id: toolUseID || "oc-ask",
    cwd,
    command,
    verdict,
    ...(bypassSandbox ? { bypass_sandbox: true } : {}),
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
  rawInput?: Any,
): Promise<{ decision: string; reason: string }> {
  const toolInput =
    rawInput && typeof rawInput === "object" && !Array.isArray(rawInput)
      ? { ...rawInput, command }
      : { command }
  const payload = {
    hook_event_name: event,
    tool_name: "Bash",
    session_id: sessionID,
    cwd,
    tool_input: toolInput,
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
  const pendingAsks = new Map<string, { sessionID: string; command: string; cwd: string; callID: string; bypass: boolean }>()
  const reqToCallKey = new Map<string, string>()
  const askKey = (sessionID: string, callID: string) => `${sessionID}:${callID}`
  return {
    "tool.execute.before": async (input: Any, output: Any) => {
      if (input.tool !== "bash") return
      const args = output?.args
      const command = args?.command ?? ""
      if (!command) return
      const directory = _ctx.directory ?? process.cwd()
      const cwd = resolve(directory, args?.workdir ?? args?.cwd ?? directory)
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
        args,
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
      if (decision === "ask" && sessionID && callID) {
        setBounded(pendingAsks, askKey(sessionID, callID), {
          sessionID,
          command,
          cwd,
          callID,
          bypass: extractBypassSandbox(args),
        })
      }
    },

    // tool.execute.after signature (opencode 1.4.3):
    //   input:  {tool, sessionID, callID, args}
    //   output: {title, output, metadata}
    // The command lives on input.args; the stdout/stderr/title lives on output.
    "tool.execute.after": async (input: Any, output: Any) => {
      if (input.tool !== "bash") return
      const args = input?.args
      const command = args?.command ?? ""
      if (!command) return
      const directory = _ctx.directory ?? process.cwd()
      const cwd = resolve(directory, args?.workdir ?? args?.cwd ?? directory)
      const sessionID = input.sessionID ?? ""
      const callID = input.callID ?? ""
      await askYolonot(
        "PostToolUse",
        sessionID,
        command,
        cwd,
        { output: output?.output ?? "", title: output?.title ?? "" },
        false,
        callID,
        args,
      )
    },

    event: async ({ event }: Any) => {
      const type = event?.type
      const props = event?.properties ?? event?.data ?? {}
      if (type === "permission.asked") {
        const reqID = props.id ?? ""
        const sessionID = props.sessionID ?? ""
        const callID = props.tool?.callID ?? props.source?.id ?? props.callID ?? ""
        if (reqID && sessionID && callID) {
          setBounded(reqToCallKey, reqID, askKey(sessionID, callID))
        }
        return
      }
      if (type !== "permission.replied") return
      const sessionID = props.sessionID ?? ""
      const reqID = props.requestID ?? props.permissionID ?? props.id ?? ""
      const directCallID = props.callID ?? props.tool?.callID ?? props.source?.id ?? ""
      const k = (reqID && reqToCallKey.get(reqID)) || (sessionID && directCallID ? askKey(sessionID, directCallID) : "")
      if (reqID) reqToCallKey.delete(reqID)
      if (!k) return
      const info = pendingAsks.get(k)
      if (!info) return
      pendingAsks.delete(k)
      const verdict = mapReplyToVerdict(props.reply ?? props.response ?? props.decision)
      if (!verdict) return
      await resolveYolonot(info.sessionID, info.command, info.cwd, verdict, false, info.callID, info.bypass)
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
    type AskState = {
      command: string
      cwd: string
      sessionID: string
      id: string
      bypass: boolean
      resolved: boolean
      resolving: Promise<void> | null
    }
    const evalPending = new Map<string, { decision: string; reason: string }>()
    const askPending = new Map<string, AskState>()
    const reqToCallKey = new Map<string, string>()
    const key = (sessionID: string, id: string) => JSON.stringify([sessionID, id])
    const directory = ctx.location.directory
    let disposed = false
    let activeStream: Any = null

    const resolveOnce = async (info: AskState, callKey: string, verdict: "allow-once" | "allow-session" | "deny") => {
      if (info.resolved) {
        if (info.resolving) await info.resolving
        return
      }
      info.resolved = true
      askPending.delete(callKey)
      // In V2 (nativeAsk=true), PostToolUse already records allow_once for
      // approved one-shot executions; only session grants and rejections need
      // explicit mod resolve.
      if (verdict === "allow-once") return
      info.resolving = resolveYolonot(info.sessionID, info.command, info.cwd, verdict, true, info.id, info.bypass)
      await info.resolving
    }

    const handleBusEvent = async (rawEv: Any) => {
      const event = rawEv?.event ?? rawEv
      const type = event?.type
      const props = event?.data ?? event?.properties ?? event ?? {}
      if (type === "permission.asked") {
        if (props.action && props.action !== "shell") return
        const reqID = props.id ?? ""
        const sessionID = props.sessionID ?? ""
        const callID = props.source?.id ?? props.tool?.callID ?? props.callID ?? ""
        if (reqID && sessionID && callID) {
          setBounded(reqToCallKey, reqID, key(sessionID, callID))
        }
        return
      }
      if (type !== "permission.replied") return
      const sessionID = props.sessionID ?? ""
      const reqID = props.requestID ?? props.permissionID ?? props.id ?? ""
      const directCallID = props.callID ?? props.source?.id ?? props.tool?.callID ?? ""
      const callKey = (reqID && reqToCallKey.get(reqID)) || (sessionID && directCallID ? key(sessionID, directCallID) : "")
      if (reqID) reqToCallKey.delete(reqID)
      if (!callKey) return
      const info = askPending.get(callKey)
      if (!info) return
      const verdict = mapReplyToVerdict(props.reply ?? props.response ?? props.decision)
      if (!verdict) return
      await resolveOnce(info, callKey, verdict)
    }

    await ctx.permission.hook("evaluate", async (event: Any) => {
      if (event.action !== "shell" || event.source?.type !== "tool") return
      const verdict = evalPending.get(key(event.sessionID, event.source.id))
      if (!verdict || event.effect === "deny") return
      event.effect = verdict.decision
      if (verdict.reason) event.message = `yolonot: ${verdict.reason}`
    })

    if (typeof ctx.event?.subscribe === "function") {
      ;(async () => {
        try {
          const sub = await ctx.event.subscribe({ types: ["permission.asked", "permission.replied"] })
          if (sub && typeof sub[Symbol.asyncIterator] === "function") {
            activeStream = sub
            for await (const ev of sub) {
              if (disposed) break
              await handleBusEvent(ev)
            }
          }
        } catch {
          // Ignore stream shutdown errors on dispose.
        }
      })()
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
            const callID = context.id ?? ""
            const callKey = key(context.sessionID, callID)
            const verdict = await askYolonot("PreToolUse", context.sessionID, command, cwd, undefined, true, callID, input)
            if (verdict.decision === "deny") throw new Error(`yolonot: ${verdict.reason || "deny"}`)
            // Empty output is passthrough, not an instruction to override
            // OpenCode's own permission policy.
            if (verdict.decision !== "") evalPending.set(callKey, verdict)
            let askInfo: AskState | null = null
            if (verdict.decision === "ask" && context.sessionID && callID) {
              askInfo = {
                command,
                cwd,
                sessionID: context.sessionID,
                id: callID,
                bypass: extractBypassSandbox(input),
                resolved: false,
                resolving: null,
              }
              setBounded(askPending, callKey, askInfo)
            }
            try {
              const result = await execute(input, context)
              if (askInfo) {
                if (!askInfo.resolved) await new Promise((r) => setTimeout(r, 20))
                if (askInfo.resolving) await askInfo.resolving
                askPending.delete(callKey)
              }
              await askYolonot("PostToolUse", context.sessionID, command, cwd, result, true, callID, input)
              return result
            } catch (err: Any) {
              if (askInfo) {
                if (!askInfo.resolved) await new Promise((r) => setTimeout(r, 20))
                if (!askInfo.resolved && String(err?.name || err || "").includes("DeclinedError")) {
                  await resolveOnce(askInfo, callKey, "deny")
                } else if (askInfo.resolving) {
                  await askInfo.resolving
                }
                askPending.delete(callKey)
              }
              throw err
            } finally {
              evalPending.delete(callKey)
            }
          }
        })
      }
    })
    return () => {
      disposed = true
      evalPending.clear()
      askPending.clear()
      reqToCallKey.clear()
      try {
        activeStream?.return?.()
      } catch {}
    }
  },
}
