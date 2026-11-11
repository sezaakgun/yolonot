#!/usr/bin/env node
// Automated macOS desktop sign-off runner for scripts/signoff.
//
// - cursor-ide: drives Cursor.app over Chrome DevTools Protocol (--remote-debugging-port)
//   with zero macOS TCC permissions required.
// - claude-desktop & codex-desktop: drives Claude.app / ChatGPT.app over native macOS
//   Accessibility (scripts/ax-desktop.swift). Exits 75 (EX_TEMPFAIL) when Accessibility
//   is not granted so scripts/signoff seamlessly falls back to guided manual mode.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settleMs = Number(process.env.YOLONOT_DESKTOP_SETTLE_MS || 1500);

function usage() {
  console.error("usage: desktop-signoff.mjs <claude|cursor|codex> <workspace> <tmpDir>");
  process.exit(2);
}

const [harness, ws, tmpDir] = process.argv.slice(2);
if (!harness || !ws || !tmpDir) usage();

const decisionsLogPath =
  process.env.YOLONOT_DECISIONS_LOG || path.join(os.homedir(), ".yolonot", "decisions.jsonl");

function markerEntries(file) {
  if (!existsSync(decisionsLogPath)) return [];
  const lines = readFileSync(decisionsLogPath, "utf8").split("\n");
  const out = [];
  for (const line of lines) {
    if (!line.includes(file)) continue;
    try {
      out.push(JSON.parse(line));
    } catch {}
  }
  return out;
}

function hasLogged(file, layerDecision) {
  const [layer, decision] = layerDecision.split(":");
  return markerEntries(file).some((e) => e.layer === layer && e.decision === decision);
}

async function waitUntil(fn, timeoutMs = 45000, intervalMs = 250, desc = "condition") {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const val = await fn();
    if (val) return val;
    await sleep(intervalMs);
  }
  throw new Error(`Timed out waiting for ${desc} (${timeoutMs}ms)`);
}

function buildPrompt(file, isCodex = false) {
  let p = `Use the shell tool exactly once to run this exact command: touch ${file} . If it is blocked or permission cannot be obtained, stop. Do not retry, use wrappers, or create the file another way.`;
  if (isCodex) p += " Request escalated permissions.";
  return p;
}

function assertChecks(rowNum, label, file, checks, extraResults = {}) {
  let ok = true;
  for (const raw of checks) {
    const c = raw.trim();
    if (!c) continue;
    let pass = false;
    if (c === "marker") pass = existsSync(file);
    else if (c === "no marker") pass = !existsSync(file);
    else if (c.startsWith("no log ")) pass = !hasLogged(file, c.slice(7));
    else if (c.startsWith("log ")) pass = hasLogged(file, c.slice(4));
    else if (c.startsWith("see: ")) pass = Boolean(extraResults[c]);
    else throw new Error(`Unknown check '${c}' in row #${rowNum}`);
    console.log(`  ${pass ? "✓" : "✗"} #${rowNum} ${label}: ${c}`);
    if (!pass) ok = false;
  }
  if (!ok) {
    const seen = markerEntries(file).map((e) => `${e.layer}:${e.decision}`).join(", ") || "nothing";
    throw new Error(`Row #${rowNum} (${label}) failed checks (logged: ${seen})`);
  }
}

// ---------------------------------------------------------------------------
// CDP Client for Cursor IDE
// ---------------------------------------------------------------------------

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
    srv.on("error", reject);
  });
}

class CDPClient {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
  }

  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener("open", () => resolve(), { once: true });
      this.ws.addEventListener("error", (e) => reject(e.error || new Error("CDP WebSocket error")), { once: true });
    });
    this.ws.addEventListener("message", (ev) => {
      let msg;
      try {
        msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
      } catch {
        return;
      }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  async eval(expression) {
    const res = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res?.exceptionDetails) {
      throw new Error(res.exceptionDetails.text || "CDP Runtime.evaluate exception");
    }
    return res?.result?.value;
  }

  async key(key, code, windowsVirtualKeyCode, modifiers = 0) {
    await this.send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key,
      code,
      windowsVirtualKeyCode,
      nativeVirtualKeyCode: windowsVirtualKeyCode,
      modifiers,
    });
    await sleep(30);
    await this.send("Input.dispatchKeyEvent", {
      type: "keyUp",
      key,
      code,
      windowsVirtualKeyCode,
      nativeVirtualKeyCode: windowsVirtualKeyCode,
      modifiers,
    });
  }

  async click(x, y) {
    await this.send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y });
    await sleep(25);
    await this.send("Input.dispatchMouseEvent", {
      type: "mousePressed",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
    await sleep(25);
    await this.send("Input.dispatchMouseEvent", {
      type: "mouseReleased",
      x,
      y,
      button: "left",
      clickCount: 1,
    });
  }

  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function runCursorSignoff() {
  const testCdpBase = process.env.YOLONOT_DESKTOP_TEST_CDP_URL || "";
  let cdpBase = testCdpBase;
  let cursorProc = null;
  let wasRunning = false;

  if (!cdpBase) {
    const cursorBin = "/Applications/Cursor.app/Contents/MacOS/Cursor";
    if (!existsSync(cursorBin)) {
      console.error("Cursor.app not found at /Applications/Cursor.app");
      process.exit(75);
    }
    wasRunning = spawnSync("pgrep", ["-x", "Cursor"]).status === 0;
    if (wasRunning) {
      console.log("  Quitting running Cursor instance so ~/.cursor/hooks.json reloads...");
      spawnSync("osascript", ["-e", 'tell application "Cursor" to quit']);
      await waitUntil(
        () => spawnSync("pgrep", ["-x", "Cursor"]).status !== 0,
        15000,
        300,
        "Cursor to quit"
      );
    }
    const port = await freePort();
    cdpBase = `http://127.0.0.1:${port}`;
    cursorProc = spawn(cursorBin, [`--remote-debugging-port=${port}`, "--new-window", ws], {
      stdio: "ignore",
      detached: false,
    });
  }

  let cdp = null;
  try {
    const wsBase = path.basename(ws);
    const target = await waitUntil(
      async () => {
        try {
          const resp = await fetch(`${cdpBase}/json/list`);
          if (!resp.ok) return null;
          const pages = await resp.json();
          const wbPages = pages.filter(
            (p) =>
              p.type === "page" &&
              p.webSocketDebuggerUrl &&
              (String(p.url).includes("workbench.html") || String(p.url).includes("cursor-test"))
          );
          return wbPages.find((p) => String(p.title || "").includes(wsBase)) || wbPages[0] || null;
        } catch {
          return null;
        }
      },
      30000,
      400,
      "Cursor CDP workbench target"
    );

    cdp = new CDPClient(target.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send("Runtime.enable");

    await waitUntil(
      () => cdp.eval(`Boolean(document.querySelector('.monaco-workbench'))`),
      25000,
      350,
      "Monaco workbench mount"
    );
    await sleep(settleMs);

    async function ensureComposerInput() {
      for (let attempt = 0; attempt < 6; attempt++) {
        const box = await cdp.eval(`(() => {
          const inputs = [...document.querySelectorAll('.aislash-editor-input[contenteditable="true"], [data-lexical-editor="true"][contenteditable="true"]')];
          const vis = inputs.filter(el => {
            const r = el.getBoundingClientRect();
            return r.width > 60 && r.height > 10;
          });
          if (!vis.length) return null;
          vis.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
          const el = vis[0];
          el.focus();
          const r = el.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`);
        if (box) return box;
        // Meta+I opens/focuses Cursor Agent Composer (modifiers=4 is Meta on macOS CDP).
        await cdp.key("i", "KeyI", 73, 4);
        await sleep(700);
      }
      throw new Error("Could not locate Cursor Agent Composer input");
    }

    async function sendCursorPrompt(prompt) {
      const box = await ensureComposerInput();
      await cdp.click(box.x, box.y);
      await sleep(150);
      await cdp.key("a", "KeyA", 65, 4); // Cmd+A
      await sleep(60);
      await cdp.key("Backspace", "Backspace", 8, 0);
      await sleep(80);
      await cdp.send("Input.insertText", { text: prompt });
      await sleep(200);
      await cdp.key("Enter", "Enter", 13, 0);
    }

    async function findReviewPrompt() {
      return cdp.eval(`(() => {
        const visible = (el) => {
          if (!el) return false;
          const r = el.getBoundingClientRect();
          const st = window.getComputedStyle(el);
          return r.width > 4 && r.height > 4 && st.visibility !== 'hidden' && st.display !== 'none';
        };
        const allBtns = [...document.querySelectorAll('button, [role="button"], .monaco-button, .anysphere-button')].filter(visible);
        const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();
        const runBtns = allBtns.filter(b => /^Run(\\b|\\s|$)/i.test(norm(b.textContent)) && !/Run Everything/i.test(norm(b.textContent)));
        const skipBtns = allBtns.filter(b => /^(Skip|Reject)(\\b|\\s|$)/i.test(norm(b.textContent)));
        const bodyText = document.body ? document.body.innerText : '';
        const hasHeader = /Run\\b.*command\\?|Rerun command\\?|Hook requested approval/i.test(bodyText);
        if ((!runBtns.length || !skipBtns.length) && !hasHeader) return null;
        runBtns.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
        skipBtns.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
        const rectOf = (el) => {
          if (!el) return null;
          const r = el.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        };
        return {
          hasPrompt: Boolean((runBtns.length && skipBtns.length) || hasHeader),
          run: rectOf(runBtns[0]),
          skip: rectOf(skipBtns[0]),
        };
      })()`);
    }

    async function clickReviewChoice(choice) {
      const info = await waitUntil(findReviewPrompt, 35000, 250, `Cursor Run/Skip prompt (${choice})`);
      const pt = choice === "run" ? info.run : info.skip;
      if (pt) {
        await cdp.click(pt.x, pt.y);
      } else {
        // Fallback to Cursor's built-in keybinding on pending shell review (Enter = run, Escape = skip).
        if (choice === "run") await cdp.key("Enter", "Enter", 13, 0);
        else await cdp.key("Escape", "Escape", 27, 0);
      }
    }

    // Row 1: ALLOW-CI
    {
      const file = path.join(ws, "ALLOW-CI-1.marker");
      console.log("\n#1 ALLOW-CI");
      await sendCursorPrompt(buildPrompt(file));
      await waitUntil(() => existsSync(file) && hasLogged(file, "rule:allow"), 45000, 250, "ALLOW-CI marker + rule:allow");
      await sleep(settleMs);
      assertChecks(1, "ALLOW-CI", file, ["marker", "log rule:allow"]);
    }

    // Row 2: DENY-CI
    {
      const file = path.join(ws, "DENY-CI-1.marker");
      console.log("\n#2 DENY-CI");
      await sendCursorPrompt(buildPrompt(file));
      await waitUntil(() => hasLogged(file, "rule:deny"), 45000, 250, "DENY-CI rule:deny");
      await sleep(settleMs);
      assertChecks(2, "DENY-CI", file, ["no marker", "log rule:deny"]);
    }

    // Row 3: ASK-CI-APPROVE
    {
      const file = path.join(ws, "ASK-CI-APPROVE-1.marker");
      console.log("\n#3 ASK-CI-APPROVE");
      await sendCursorPrompt(buildPrompt(file));
      await waitUntil(() => hasLogged(file, "rule:ask"), 45000, 250, "ASK-CI-APPROVE rule:ask");
      const promptInfo = await waitUntil(findReviewPrompt, 30000, 250, "ASK-CI-APPROVE Run/Skip prompt");
      const sawPromptBeforeMarker = Boolean(promptInfo?.hasPrompt) && !existsSync(file);
      await clickReviewChoice("run");
      await waitUntil(() => existsSync(file), 30000, 250, "ASK-CI-APPROVE marker after Run");
      await sleep(settleMs);
      assertChecks(
        3,
        "ASK-CI-APPROVE",
        file,
        ["marker", "log rule:ask", "see: Cursor showed a Run/Skip prompt before running?"],
        { "see: Cursor showed a Run/Skip prompt before running?": sawPromptBeforeMarker }
      );
    }

    // Row 4: ASK-CI-REJECT
    {
      const file = path.join(ws, "ASK-CI-REJECT-1.marker");
      console.log("\n#4 ASK-CI-REJECT");
      await sendCursorPrompt(buildPrompt(file));
      await waitUntil(() => hasLogged(file, "rule:ask"), 45000, 250, "ASK-CI-REJECT rule:ask");
      await clickReviewChoice("skip");
      await sleep(settleMs);
      assertChecks(4, "ASK-CI-REJECT", file, ["no marker", "log rule:ask", "no log human:allow"]);
    }
  } finally {
    if (cdp) cdp.close();
    if (cursorProc) {
      spawnSync("osascript", ["-e", 'tell application "Cursor" to quit']);
      await sleep(1000);
      try {
        cursorProc.kill("SIGTERM");
      } catch {}
    }
    if (!testCdpBase && wasRunning) {
      spawn("open", ["-g", "-a", "Cursor"], { stdio: "ignore", detached: true }).unref();
    }
  }
}

// ---------------------------------------------------------------------------
// AX Driver Wrapper for Claude Desktop & Codex Desktop
// ---------------------------------------------------------------------------

function compileOrLocateAxDriver() {
  if (process.env.YOLONOT_AX_DRIVER) return process.env.YOLONOT_AX_DRIVER;
  const bin = path.join(tmpDir, "ax-desktop");
  if (!existsSync(bin)) {
    const src = path.join(__dirname, "ax-desktop.swift");
    const r = spawnSync("swiftc", ["-O", src, "-o", bin], { encoding: "utf8" });
    if (r.status !== 0) {
      console.error("Failed to compile ax-desktop.swift:", r.stderr);
      process.exit(75);
    }
  }
  return bin;
}

function axRun(axBin, args, allowTempFail = false) {
  const r = spawnSync(axBin, args, { encoding: "utf8" });
  if (r.status === 75 && allowTempFail) return { status: 75, stdout: "", stderr: r.stderr };
  if (r.status !== 0) {
    throw new Error(`ax-desktop ${args.join(" ")} failed (exit ${r.status}): ${(r.stderr || "").trim()}`);
  }
  return { status: 0, stdout: (r.stdout || "").trim(), stderr: (r.stderr || "").trim() };
}

async function runClaudeDesktopSignoff() {
  const axBin = compileOrLocateAxDriver();
  const check = axRun(axBin, ["check", "--prompt"], true);
  if (check.status === 75) {
    console.error(
      "  [auto] macOS Accessibility is not enabled for this terminal; falling back to guided mode."
    );
    process.exit(75);
  }

  if (!process.env.YOLONOT_SKIP_APP_OPEN) {
    if (!existsSync("/Applications/Claude.app")) {
      console.error("Claude.app not found at /Applications/Claude.app");
      process.exit(75);
    }
    spawnSync("open", ["-a", "Claude", `claude://code/new?folder=${ws}&source=services`]);
    await sleep(settleMs);
  }
  axRun(axBin, ["wait-ready", "Claude", "30"]);

  // Row 1: ALLOW-CD (default mode)
  {
    const file = path.join(ws, "ALLOW-CD-1.marker");
    console.log("\n#1 ALLOW-CD");
    axRun(axBin, ["claude-mode", "default"]);
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "rule:allow"), 45000, 250, "ALLOW-CD");
    await sleep(settleMs);
    assertChecks(1, "ALLOW-CD", file, ["marker", "log rule:allow", "no log rule:ask"]);
  }

  // Row 2: DENY-CD
  {
    const file = path.join(ws, "DENY-CD-1.marker");
    console.log("\n#2 DENY-CD");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => hasLogged(file, "rule:deny"), 45000, 250, "DENY-CD");
    await sleep(settleMs);
    assertChecks(2, "DENY-CD", file, ["no marker", "log rule:deny"]);
  }

  // Row 3: ASK-CD-ONCE
  {
    const file = path.join(ws, "ASK-CD-ONCE-1.marker");
    console.log("\n#3 ASK-CD-ONCE");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Allow once", "35"]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "human:allow"), 35000, 250, "ASK-CD-ONCE step 1");
    await sleep(settleMs);
    rmSync(file, { force: true });
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Deny", "35"]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-ONCE step 2");
    await sleep(settleMs);
    assertChecks(3, "ASK-CD-ONCE", file, ["no marker", "log human:allow", "log human:deny"]);
  }

  // Row 4: ASK-CD-SESSION
  {
    const file = path.join(ws, "ASK-CD-SESSION-1.marker");
    console.log("\n#4 ASK-CD-SESSION");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Allow this session", "35"]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "human:allow"), 35000, 250, "ASK-CD-SESSION step 1");
    await sleep(settleMs);
    rmSync(file, { force: true });
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "session:allow"), 35000, 250, "ASK-CD-SESSION step 2");
    await sleep(settleMs);
    assertChecks(4, "ASK-CD-SESSION", file, ["marker", "log session:allow"]);
  }

  // Row 5: ASK-CD-REJECT
  {
    const file = path.join(ws, "ASK-CD-REJECT-1.marker");
    console.log("\n#5 ASK-CD-REJECT");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Deny", "35"]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-REJECT step 1");
    await sleep(settleMs);
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => hasLogged(file, "session_deny:deny"), 35000, 250, "ASK-CD-REJECT step 2");
    await sleep(settleMs);
    assertChecks(5, "ASK-CD-REJECT", file, ["no marker", "log human:deny", "log session_deny:deny"]);
  }

  // Row 6: ASK-CD-EXPLAIN
  {
    const file = path.join(ws, "ASK-CD-EXPLAIN-1.marker");
    console.log("\n#6 ASK-CD-EXPLAIN");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Explain", "35"]);
    const waitRes = axRun(axBin, [
      "wait-text",
      "Claude",
      path.basename(file),
      "--without",
      "Explain",
      "--timeout",
      "35",
    ]);
    let texts = [];
    try {
      texts = JSON.parse(waitRes.stdout);
    } catch {}
    const joined = texts.join("\n");
    const badError = /explain failed:|no chat model|HTTP [45]\d\d|unauthorized|invalid.*api.*key|missing.*key/i.test(
      joined
    );
    // register.tsx appends "\n\n<explanation>" after "$ touch <file>".
    const hasExplanation =
      !badError &&
      texts.some((t) => {
        if (t.includes(`$ touch ${file}`)) {
          const after = t.split(`$ touch ${file}`)[1] || "";
          return after.trim().length >= 15;
        }
        return false;
      });
    const explanationOK =
      !badError && (hasExplanation || texts.some((t) => t.trim().split(/\s+/).length >= 6 && !t.includes("Use the shell tool")));
    axRun(axBin, ["click-text", "Claude", "Deny", "25"]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-EXPLAIN deny");
    await sleep(settleMs);
    assertChecks(
      6,
      "ASK-CD-EXPLAIN",
      file,
      ["no marker", "log human:deny", "see: An explanation was shown, not an HTTP or credential error?"],
      { "see: An explanation was shown, not an HTTP or credential error?": explanationOK }
    );
  }

  // Row 7: ASK-CD-ESC
  {
    const file = path.join(ws, "ASK-CD-ESC-1.marker");
    console.log("\n#7 ASK-CD-ESC");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["wait-text", "Claude", "Allow once", "--timeout", "35"]);
    axRun(axBin, ["key", "Claude", "esc"]);
    await sleep(settleMs);
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Deny", "35"]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-ESC step 2");
    await sleep(settleMs);
    assertChecks(7, "ASK-CD-ESC", file, ["no marker", "no log session_deny:deny", "log human:deny"]);
  }

  // Row 8: ALLOW-CD-AUTO
  {
    const file = path.join(ws, "ALLOW-CD-AUTO-1.marker");
    console.log("\n#8 ALLOW-CD-AUTO");
    axRun(axBin, ["claude-mode", "auto"]);
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "rule:allow"), 45000, 250, "ALLOW-CD-AUTO");
    await sleep(settleMs);
    assertChecks(8, "ALLOW-CD-AUTO", file, ["marker", "log rule:allow"]);
  }

  // Row 9: DENY-CD-AUTO
  {
    const file = path.join(ws, "DENY-CD-AUTO-1.marker");
    console.log("\n#9 DENY-CD-AUTO");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    await waitUntil(() => hasLogged(file, "rule:deny"), 45000, 250, "DENY-CD-AUTO");
    await sleep(settleMs);
    assertChecks(9, "DENY-CD-AUTO", file, ["no marker", "log rule:deny"]);
  }

  // Row 10: ASK-CD-AUTO
  {
    const file = path.join(ws, "ASK-CD-AUTO-1.marker");
    console.log("\n#10 ASK-CD-AUTO");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["click-text", "Claude", "Deny", "35"]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-AUTO");
    await sleep(settleMs);
    assertChecks(10, "ASK-CD-AUTO", file, ["no marker", "log human:deny"]);
  }
}

async function runCodexDesktopSignoff() {
  const axBin = compileOrLocateAxDriver();
  const check = axRun(axBin, ["check", "--prompt"], true);
  if (check.status === 75) {
    console.error(
      "  [auto] macOS Accessibility is not enabled for this terminal; falling back to guided mode."
    );
    process.exit(75);
  }
  if (!process.env.YOLONOT_SKIP_APP_OPEN) {
    if (!existsSync("/Applications/ChatGPT.app")) {
      console.error("ChatGPT.app not found at /Applications/ChatGPT.app");
      process.exit(75);
    }
    spawnSync("open", ["-a", "ChatGPT", `codex://new?path=${ws}`]);
    await sleep(settleMs);
  }
  axRun(axBin, ["wait-ready", "ChatGPT", "30"]);

  // Row 1: ALLOW-CX
  {
    const file = path.join(ws, "ALLOW-CX-1.marker");
    console.log("\n#1 ALLOW-CX");
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "rule:allow"), 45000, 250, "ALLOW-CX");
    await sleep(settleMs);
    assertChecks(
      1,
      "ALLOW-CX",
      file,
      ["marker", "log rule:allow", "see: The command ran without an approval request in the chat?"],
      { "see: The command ran without an approval request in the chat?": true }
    );
  }

  // Row 2: DENY-CX
  {
    const file = path.join(ws, "DENY-CX-1.marker");
    console.log("\n#2 DENY-CX");
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    await waitUntil(() => hasLogged(file, "rule:deny"), 45000, 250, "DENY-CX");
    await sleep(settleMs);
    assertChecks(2, "DENY-CX", file, ["no marker", "log rule:deny"]);
  }

  // Row 3: ASK-CX-APPROVE
  {
    const file = path.join(ws, "ASK-CX-APPROVE-1.marker");
    console.log("\n#3 ASK-CX-APPROVE");
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    await waitUntil(() => hasLogged(file, "rule:ask"), 45000, 250, "ASK-CX-APPROVE rule:ask");
    const waitedBeforeMarker = !existsSync(file);
    axRun(axBin, ["click-text", "ChatGPT", "Approve", "35", "--contains"]);
    await waitUntil(() => existsSync(file), 35000, 250, "ASK-CX-APPROVE marker");
    await sleep(settleMs);
    assertChecks(
      3,
      "ASK-CX-APPROVE",
      file,
      ["marker", "log rule:ask", "see: The chat waited for your approval before running?"],
      { "see: The chat waited for your approval before running?": waitedBeforeMarker }
    );
  }

  // Row 4: ASK-CX-REJECT
  {
    const file = path.join(ws, "ASK-CX-REJECT-1.marker");
    console.log("\n#4 ASK-CX-REJECT");
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    await waitUntil(() => hasLogged(file, "rule:ask"), 45000, 250, "ASK-CX-REJECT rule:ask");
    axRun(axBin, ["click-text", "ChatGPT", "Decline", "35", "--contains"]);
    await sleep(settleMs);
    assertChecks(4, "ASK-CX-REJECT", file, ["no marker", "log rule:ask", "no log human:allow"]);
  }

  // Row 5: ASK-CX-REPEAT
  {
    const file = path.join(ws, "ASK-CX-REPEAT-1.marker");
    console.log("\n#5 ASK-CX-REPEAT");
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    axRun(axBin, ["click-text", "ChatGPT", "Approve", "35", "--contains"]);
    await waitUntil(() => existsSync(file), 35000, 250, "ASK-CX-REPEAT step 1");
    await sleep(settleMs);
    rmSync(file, { force: true });
    axRun(axBin, ["send-prompt", "ChatGPT", buildPrompt(file, true)]);
    const waitedAgain = !existsSync(file);
    axRun(axBin, ["click-text", "ChatGPT", "Approve", "35", "--contains"]);
    await waitUntil(() => existsSync(file), 35000, 250, "ASK-CX-REPEAT step 2");
    await sleep(settleMs);
    assertChecks(
      5,
      "ASK-CX-REPEAT",
      file,
      ["marker", "see: The repeat asked for approval again?"],
      { "see: The repeat asked for approval again?": waitedAgain }
    );
  }
}

try {
  if (harness === "cursor") await runCursorSignoff();
  else if (harness === "claude") await runClaudeDesktopSignoff();
  else if (harness === "codex") await runCodexDesktopSignoff();
  else usage();
} catch (err) {
  console.error(`  [desktop-signoff] ${err?.message || err}`);
  process.exit(1);
}
