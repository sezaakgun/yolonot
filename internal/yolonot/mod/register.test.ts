import { expect, test } from 'bun:test'

// Claude provides its own JSX runtime. Compile the production module with
// that classic JSX convention without installing React for this test.
const transpiler = new Bun.Transpiler({ loader: 'tsx', tsconfig: { compilerOptions: { jsx: 'react', jsxFactory: 'h' } } })
const source = transpiler.transformSync(await Bun.file(new URL('./register.tsx', import.meta.url)).text())
const register = new Function(source.replace('export const register', 'const register') + '\nreturn register;')()

test('a previous rejection still consults the core for pause and policy updates', async () => {
  const handlers = new Map<string, any>()
  register(((name: string, ...args: any[]) => handlers.set(name, args.at(-1))) as any)
  let verdict: 'ask' | 'allow' | 'deny' | '' = 'ask'
  let hookCalls = 0
  let resolveCalls = 0
  let nextCalls = 0
  const $ = {
    session: { id: async () => 'middleware-regression', cwd: async () => '/tmp' },
    process: {
      run: async (args: string[]) => {
        if (args[1] === 'mod' && args[2] === 'resolve') {
          resolveCalls++
          return { stdout: '', stderr: '', exitCode: 0 }
        }
        expect(args[1]).toBe('hook')
        hookCalls++
        return { stdout: verdict ? JSON.stringify({ hookSpecificOutput: { permissionDecision: verdict } }) : '', stderr: '', exitCode: 0 }
      },
    },
    ui: { ask: async () => 'Deny', invalidate: () => {} },
  }
  await handlers.get('session.start')($, {}, async (event: any) => event)
  const next = async () => { nextCalls++; return { continued: true } }
  const invoke = (id: string) => handlers.get('tool.call')($, { tool: 'Bash', command: 'review-rejected', tool_use_id: id }, next)
  expect((await invoke('initial')).deny).toContain('user rejected')
  expect(resolveCalls).toBe(1)

  // An empty result is the core's pause/disabled/passthrough contract.
  verdict = ''
  expect(await invoke('paused')).toEqual({ continued: true })
  verdict = 'allow'
  expect(await invoke('new-allow-rule')).toEqual({ continued: true })
  verdict = 'deny'
  expect((await invoke('new-deny-rule')).deny).toContain('yolonot')
  expect(hookCalls).toBe(4)
  expect(nextCalls).toBe(2)
})

for (const choice of ['Allow once', 'Allow this session', 'Deny', 'Explain', 'Explain-error', 'dialog-error', 'dialog-dismissed']) {
  test(`ask dialog resolves ${choice} with the bound tool invocation`, async () => {
    const handlers = new Map<string, any>()
    register(((name: string, ...args: any[]) => handlers.set(name, args.at(-1))) as any)
    const resolutions: any[] = []
    const dialogs: any[] = []
    let explains = 0
    let executions = 0
    const $ = {
      session: { id: async () => 'dialog-session', cwd: async () => '/test-project' },
      process: { run: async (args: string[], options: any) => {
        if (args[1] === 'hook') return { stdout: JSON.stringify({ hookSpecificOutput: { permissionDecision: 'ask', permissionDecisionReason: 'confirm fixture' } }), stderr: '', exitCode: 0 }
        if (args[1] === 'explain') { explains++; return choice === 'Explain-error' ? {stdout: '', stderr: 'explain failed: missing API key', exitCode: 1} : { stdout: 'Fixture explanation', stderr: '', exitCode: 0 } }
        if (args[1] === 'mod' && args[2] === 'resolve') { resolutions.push(JSON.parse(options.stdin)); return { stdout: '', stderr: '', exitCode: 0 } }
        throw new Error('Unexpected process call')
      } },
      ui: { invalidate: () => {}, ask: async (prompt: string, options: any) => {
        dialogs.push({ prompt, options: options.options })
        if (choice === 'dialog-error') throw new Error('dialog unavailable')
        if (choice === 'dialog-dismissed') return ''
        return choice.startsWith('Explain') ? (dialogs.length > 1 ? 'Allow once' : 'Explain') : choice
      } },
    }
    await handlers.get('session.start')($, {}, async (event: any) => event)
    const result = await handlers.get('tool.call')($, { tool: 'Bash', command: 'fixture command', tool_use_id: 'tool-dialog-1' }, async () => { executions++; return { executed: true } })
    const unanswered = choice === 'dialog-error' || choice === 'dialog-dismissed'
    const denied = choice === 'Deny' || unanswered
    expect(executions).toBe(denied ? 0 : 1)
    if (unanswered) {
      expect(result.deny).toContain('not approved')
      expect(result.deny).not.toContain('user rejected')
      expect(resolutions).toEqual([])
      return
    }
    if (denied) expect(result.deny).toContain('user rejected')
    expect(resolutions).toEqual([{ session_id: 'dialog-session', tool_use_id: 'tool-dialog-1', cwd: '/test-project', command: 'fixture command', verdict: denied ? 'deny' : choice === 'Allow this session' ? 'allow-session' : 'allow-once', reason: 'confirm fixture' }])
    expect(dialogs[0].options).toEqual(['Allow once', 'Allow this session', 'Explain', 'Deny'])
    expect(explains).toBe(choice.startsWith('Explain') ? 1 : 0)
    if (choice === 'Explain-error') {
      expect(dialogs[1].prompt).toContain('explain failed: missing API key')
      expect(dialogs[1].prompt).not.toContain('explain failed: explain failed:')
      expect(dialogs[1].options).toEqual(['Allow once', 'Allow this session', 'Deny'])
    }
    if (choice === 'Explain') {
      expect(dialogs[1].prompt).toContain('Fixture explanation')
      expect(dialogs[1].options).toEqual(['Allow once', 'Allow this session', 'Deny'])
    }
  })
}
