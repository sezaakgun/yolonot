/* @jsx h */
import type { Register } from 'claude-code'

// yolonot's Claude Code mod. Written by `yolonot install --mod`; the binary
// path below is filled in at install time.
//
// tool.call: runs `yolonot hook` for every Bash call (YOLONOT_MOD=1), so the
//   verdict is known before Claude's own permission path. allow → the call goes
//   on; deny → refused; ask → a four-way dialog. The classic settings hook then
//   replays the recorded verdict for the same tool_use_id instead of judging again.
// ui.render ToolUse: a dim verdict line under each Bash row.

const BIN = '__YOLONOT_BIN__'

type Entry = { decision: string; layer: string; reason: string; ms: number }
const entries = new Map<string, Entry>()
let sid = ''

const firstLine = (s: string) => s.split('\n')[0]
const VARIANT_NOTE = ' The user already rejected this command this session: do not retry it through a wrapper, heredoc or variable path; ask the user instead.'
// banners read "🧑‍🚀 <layer> -> <text>"
const parseBanner = (s: string) => {
  const m = /^🧑‍🚀 (\S+) -> ([\s\S]*)$/.exec(s)
  return m ? { layer: m[1], text: m[2] } : { layer: '', text: s }
}

async function judge($: any, command: string, id: string, cwd: string, ev?: any): Promise<Entry> {
  const toolInput: Record<string, any> = { command }
  if (ev?.dangerouslyDisableSandbox === true || ev?.input?.dangerouslyDisableSandbox === true) {
    toolInput.dangerouslyDisableSandbox = true
  }
  const payload: Record<string, any> = { hook_event_name: 'PreToolUse', tool_name: ev?.tool || 'Bash', session_id: sid, cwd, tool_use_id: id, tool_input: toolInput }
  if (typeof ev?.permission_mode === 'string' && ev.permission_mode) {
    payload.permission_mode = ev.permission_mode
  }
  const t0 = Date.now()
  const r = await $.process.run([BIN, 'hook'], { stdin: JSON.stringify(payload), env: { YOLONOT_MOD: '1' }, timeoutMs: 65000 })
  const ms = Date.now() - t0
  // Empty output with exit 0 is the core's pause/passthrough answer; any
  // other unreadable answer fails closed like the classic hook's onFailure.
  if (r.exitCode === 0 && !r.stdout.trim()) return { decision: '', layer: '', reason: '', ms }
  let decision = ''
  let banner = ''
  let parsed = false
  try {
    const j = JSON.parse(r.stdout)
    decision = j.hookSpecificOutput?.permissionDecision ?? ''
    banner = j.hookSpecificOutput?.permissionDecisionReason || j.systemMessage || ''
    parsed = true
  } catch {}
  if (r.exitCode !== 0 || !parsed) return { decision: 'deny', layer: 'error', reason: 'safety check failed; this call was not approved.', ms }
  const b = parseBanner(banner)
  // the allow banner carries the command, not a reason
  return { decision, layer: b.layer, reason: decision === 'allow' ? '' : b.text, ms }
}

async function resolve($: any, verdict: string, id: string, cwd: string, command: string, reason: string) {
  await $.process.run([BIN, 'mod', 'resolve'], { stdin: JSON.stringify({ session_id: sid, tool_use_id: id, cwd, command, verdict, reason }) })
}

async function explain($: any, command: string, reason: string): Promise<string> {
  const r = await $.process.run([BIN, 'explain'], { stdin: JSON.stringify({ command, reason }), timeoutMs: 30000 })
  if (r.exitCode === 0) return r.stdout.trim()
  const error = r.stderr.trim() || 'no chat model'
  return error.startsWith('explain failed:') ? error : 'explain failed: ' + error
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    sid = await $.session.id()
    return next(e)
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const command = e.tool === 'Bash' ? (e as any).command : undefined
    const id = e.tool_use_id ?? ''
    if (!sid || typeof command !== 'string' || !command || !id) return next(e)
    // The mod cannot see a subagent's or teammate's working directory, so the
    // classic hook, which gets the real one, judges those calls alone.
    if (e.agentId) return next(e)
    const cwd = await $.session.cwd()
    // The Go hook owns rejection memory and current policy precedence,
    // including pause, explicit allow rules and shell-wrapped retries.
    const h = await judge($, command, id, cwd, e)
    entries.set(id, h)
    $.ui.invalidate('ui.render')
    if (h.decision === 'deny') {
      return { deny: 'yolonot: ' + h.reason + (h.layer === 'session_deny' ? VARIANT_NOTE : '') }
    }
    if (h.decision !== 'ask') return next(e)
    let explanation = ''
    for (;;) {
      const q = `yolonot: ${h.reason}\n\n$ ${command}` + (explanation ? `\n\n${explanation}` : '')
      const options = explanation ? ['Allow once', 'Allow this session', 'Deny'] : ['Allow once', 'Allow this session', 'Explain', 'Deny']
      let a: string
      try { a = await $.ui.ask(q, { options, header: 'yolonot' }) } catch {
        return { deny: 'yolonot: approval dialog unavailable; this call was not approved.' }
      }
      if (!options.includes(a)) return { deny: 'yolonot: no approval answer; this call was not approved.' }
      if (a === 'Explain') { explanation = await explain($, command, h.reason); continue }
      const verdict = a === 'Allow once' ? 'allow-once' : a === 'Allow this session' ? 'allow-session' : 'deny'
      await resolve($, verdict, id, cwd, command, h.reason)
      h.decision = verdict === 'deny' ? 'deny' : 'allow'
      h.layer = 'human'
      h.reason = verdict === 'deny' ? 'rejected' : verdict === 'allow-once' ? 'allowed once' : 'allowed this session'
      $.ui.invalidate('ui.render')
      if (verdict === 'deny') {
        return { deny: 'yolonot: the user rejected this command.' + VARIANT_NOTE }
      }
      return next(e)
    }
  }).catch(($, e, next) => next.called ? next(e) : { deny: 'yolonot: safety check failed; this call was not approved.' })

  const verdictLine = (Text: any, en: Entry, command: string, cols: number) => {
    const color = en.decision === 'deny' ? 'red' : en.layer === 'human' || en.decision === 'ask' ? 'yellow' : 'green'
    const detail = en.decision === 'allow' && en.layer !== 'human' ? '' : en.reason ? ' · ' + firstLine(en.reason) : ''
    const head = `  ● yolonot ${en.layer || en.decision}${en.ms ? ' · ' + en.ms + ' ms' : ''}${detail}`
    const room = Math.max(0, cols - head.length - 4)
    const cmd = command ? ' · ' + (command.length > room ? command.slice(0, Math.max(0, room - 1)) + '…' : command) : ''
    return <Text dimColor>  <Text color={color}>●</Text> yolonot {en.layer || en.decision}{en.ms ? ' · ' + en.ms + ' ms' : ''}{detail}{cmd}</Text>
  }

  // the transcript folds Bash calls into a ToolGroup line ("Ran 1 shell
  // command"); the verdicts go under that line, one per judged call, with the
  // command the fold hides. Expanded groups draw ToolUse rows instead.
  on('ui.render', { component: 'ToolGroup' }, async ($, e, next) => {
    const hits = e.props.calls.filter(c => c.tool_use_id && entries.has(c.tool_use_id))
    if (e.props.expanded || hits.length === 0) return next(e)
    const { Box, Text } = await $.ui.resolve(e)
    const tree = await next(e)
    const cols = e.viewport?.columns ?? 100
    return (
      <Box flexDirection="column">
        {tree}
        {hits.map(c => verdictLine(Text, entries.get(c.tool_use_id!)!, String((c.input as any)?.command ?? ''), cols))}
      </Box>
    )
  })

  on('ui.render', { component: 'ToolUse' }, async ($, e, next) => {
    const en = entries.get(e.props.tool_use_id)
    if (!en || (e.props.toolName !== 'Bash' && e.props.toolName !== 'PowerShell')) return next(e)
    const { Box, Text } = await $.ui.resolve(e)
    const tree = await next(e)
    return (
      <Box flexDirection="column">
        {tree}
        {verdictLine(Text, en, '', e.viewport?.columns ?? 100)}
      </Box>
    )
  })
}
