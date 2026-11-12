#!/usr/bin/env node
// Automated macOS desktop sign-off runner for scripts/signoff.
//
// - cursor-ide & codex-desktop: drives Cursor.app / ChatGPT.app over Chrome DevTools
//   Protocol (--remote-debugging-port) with zero macOS TCC permissions required.
// - claude-desktop: drives Claude.app over native macOS Accessibility
//   (scripts/ax-desktop.swift). Exits 75 (EX_TEMPFAIL) when Accessibility is not
//   granted so scripts/signoff seamlessly falls back to guided manual mode.

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
  // Count active poll iterations rather than wall-clock Date.now() so brief
  // macOS App Nap / sleep transitions never expire a check after 1 poll.
  const maxPolls = Math.max(2, Math.ceil(timeoutMs / Math.max(20, intervalMs)));
  for (let i = 0; i < maxPolls; i++) {
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
      this.ws.addEventListener("close", () => reject(new Error("CDP WebSocket closed during connect")), { once: true });
    });
    const rejectAll = (reason) => {
      for (const { reject } of this.pending.values()) {
        reject(new Error(reason));
      }
      this.pending.clear();
    };
    this.ws.addEventListener("close", () => rejectAll("CDP WebSocket closed"));
    this.ws.addEventListener("error", () => rejectAll("CDP WebSocket error"));
    this.ws.addEventListener("message", (ev) => {
      let msg;
      try {
        msg = JSON.parse(typeof ev.data === "string" ? ev.data : ev.data.toString());
      } catch {
        return;
      }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject, timer } = this.pending.get(msg.id);
        clearTimeout(timer);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    });
  }

  isOpen() {
    return this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  send(method, params = {}) {
    if (!this.isOpen()) {
      return Promise.reject(new Error("CDP WebSocket is not open"));
    }
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP ${method} timed out`));
        }
      }, 15000);
      this.pending.set(id, { resolve, reject, timer });
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
    const extra = key === "Enter" && modifiers === 0 ? { text: "\r", unmodifiedText: "\r" } : {};
    await this.send("Input.dispatchKeyEvent", {
      type: "keyDown",
      key,
      code,
      windowsVirtualKeyCode,
      nativeVirtualKeyCode: windowsVirtualKeyCode,
      modifiers,
      ...extra,
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
  let launchedViaOpen = false;
  let wasRunning = false;

  if (!cdpBase) {
    if (!existsSync("/Applications/Cursor.app")) {
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
    // Launch via macOS LaunchServices (`open -a`) so Cursor gets a clean GUI
    // environment (no inherited agent/CLI env vars) and registers `ws`.
    spawnSync("open", [
      "-a",
      "Cursor",
      "--args",
      `--remote-debugging-port=${port}`,
      "--disable-workspace-trust",
      ws,
    ]);
    launchedViaOpen = true;
  }

  let cdp = null;
  try {
    const wsBase = path.basename(ws);
    const listWorkbenchPages = async () => {
      try {
        const resp = await fetch(`${cdpBase}/json/list`);
        if (!resp.ok) return [];
        const pages = await resp.json();
        return pages.filter(
          (p) =>
            p.type === "page" &&
            p.webSocketDebuggerUrl &&
            (String(p.url).includes("workbench.html") || String(p.url).includes("cursor-test"))
        );
      } catch {
        return [];
      }
    };

    let wbPages = await waitUntil(
      async () => {
        const p = await listWorkbenchPages();
        return p.length ? p : null;
      },
      30000,
      400,
      "Cursor CDP workbench target"
    );
    let target = wbPages.find((p) => String(p.title || "").includes(wsBase)) || wbPages[0];

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

    // Once workbench is mounted, send LaunchServices open on `ws` so Cursor
    // Agents / IDE binds the session to `ws` (rather than "No Repo").
    if (!testCdpBase) {
      spawnSync("open", ["-a", "Cursor", ws]);
      await sleep(2500);
      wbPages = await listWorkbenchPages();
      const wsPage = wbPages.find((p) => String(p.title || "").includes(wsBase));
      if (wsPage && wsPage.webSocketDebuggerUrl !== target.webSocketDebuggerUrl) {
        cdp.close();
        target = wsPage;
        cdp = new CDPClient(target.webSocketDebuggerUrl);
        await cdp.connect();
        await cdp.send("Runtime.enable");
        await waitUntil(
          () => cdp.eval(`Boolean(document.querySelector('.monaco-workbench'))`),
          20000,
          300,
          "Workspace workbench mount"
        );
        await sleep(settleMs);
      } else if (target.title === "Cursor Agents") {
        // In Cursor Agents hub, ensure our workspace section/pill is selected (not "No Repo").
        await waitUntil(
          () => cdp.eval(`document.body && document.body.innerText.includes(${JSON.stringify(wsBase)})`),
          10000,
          300,
          "Cursor Agents workspace registration"
        ).catch(() => null);
      }
      console.log(
        `  Connected to Cursor window: "${target.title}" (pages: ${JSON.stringify(wbPages.map((p) => p.title))})`
      );
    }

    async function ensureComposerInput() {
      for (let attempt = 0; attempt < 8; attempt++) {
        const box = await cdp.eval(`(() => {
          const selectors = [
            '.aislash-editor-input:not(.aislash-editor-input-readonly) [contenteditable="true"]',
            '.aislash-editor-input[contenteditable="true"]',
            '.full-input-box [contenteditable="true"]',
            '.ai-input-full-input-box [contenteditable="true"]',
            '.ProseMirror[contenteditable="true"]',
            '[data-lexical-editor="true"][contenteditable="true"]',
            '.full-input-box textarea',
          ];
          const seen = new Set();
          const inputs = [];
          for (const sel of selectors) {
            for (const el of document.querySelectorAll(sel)) {
              if (el.closest('.aislash-editor-input-readonly')) continue;
              if (!seen.has(el)) {
                seen.add(el);
                inputs.push(el);
              }
            }
          }
          const vis = inputs.filter(el => {
            const r = el.getBoundingClientRect();
            const st = window.getComputedStyle(el);
            return r.width > 40 && r.height > 8 && st.visibility !== 'hidden' && st.display !== 'none';
          });
          if (!vis.length) return null;
          vis.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
          const el = vis[0];
          el.focus();
          const r = el.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`);
        if (box) return box;
        // Meta+I (and fallback Meta+L) opens/focuses Cursor Agent Composer on macOS CDP.
        if (attempt % 2 === 0) {
          await cdp.key("i", "KeyI", 73, 4);
        } else {
          await cdp.key("l", "KeyL", 76, 4);
        }
        await sleep(800);
      }
      const debugInfo = await cdp.eval(`(() => ({
        title: document.title,
        editables: [...document.querySelectorAll('[contenteditable], textarea')].slice(0, 10).map(e => ({
          tag: e.tagName,
          cls: String(e.className || '').slice(0, 80),
          ce: e.getAttribute('contenteditable'),
          w: Math.round(e.getBoundingClientRect().width),
          h: Math.round(e.getBoundingClientRect().height),
        })),
      }))()`).catch(() => null);
      throw new Error("Could not locate Cursor Agent Composer input: " + JSON.stringify(debugInfo));
    }

    async function sendCursorPrompt(prompt) {
      const box = await ensureComposerInput();
      await cdp.click(box.x, box.y);
      await sleep(150);
      // Ensure Composer is in Agent mode (not Ask/Plan) if a mode selector pill is present.
      const modeSwitch = await cdp.eval(`(() => {
        const boxEl = document.querySelector('.ai-input-full-input-box, .full-input-box');
        if (!boxEl) return null;
        const els = [...boxEl.querySelectorAll('button, [role="button"], span, div')];
        const modeBtn = els.find(el => {
          const t = (el.textContent || '').trim();
          const r = el.getBoundingClientRect();
          return (t === 'Ask' || t === 'Plan' || t === 'Manual' || t === 'Edit') && r.width > 16 && r.width < 120 && r.height > 12 && r.height < 40;
        });
        if (!modeBtn) return null;
        const r = modeBtn.getBoundingClientRect();
        return { text: (modeBtn.textContent || '').trim(), x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (modeSwitch) {
        await cdp.click(modeSwitch.x, modeSwitch.y);
        await sleep(300);
        const agentItem = await cdp.eval(`(() => {
          const items = [...document.querySelectorAll('[role="menuitem"], [role="option"], .monaco-action-bar .action-item, div, span')];
          const hit = items.find(el => {
            const t = (el.textContent || '').trim();
            const r = el.getBoundingClientRect();
            return /^Agent$/i.test(t) && r.width > 20 && r.width < 220 && r.height > 12 && r.height < 45;
          });
          if (!hit) return null;
          const r = hit.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`);
        if (agentItem) {
          await cdp.click(agentItem.x, agentItem.y);
          await sleep(250);
        }
        await cdp.click(box.x, box.y);
        await sleep(120);
      }

      await cdp.key("a", "KeyA", 65, 4); // Cmd+A
      await sleep(60);
      await cdp.key("Backspace", "Backspace", 8, 0);
      await sleep(80);
      // execCommand('insertText') triggers Lexical/ProseMirror beforeinput handlers reliably;
      // fall back to CDP Input.insertText if editor remained empty.
      const insertedViaExec = await cdp.eval(`(() => {
        const selectors = [
          '.aislash-editor-input:not(.aislash-editor-input-readonly) [contenteditable="true"]',
          '.aislash-editor-input[contenteditable="true"]',
          '.full-input-box [contenteditable="true"]',
          '.ProseMirror[contenteditable="true"]',
          '[data-lexical-editor="true"][contenteditable="true"]',
        ];
        for (const sel of selectors) {
          const el = document.querySelector(sel);
          if (el && !el.closest('.aislash-editor-input-readonly')) {
            el.focus();
            document.execCommand('selectAll', false, null);
            document.execCommand('insertText', false, ${JSON.stringify(prompt)});
            if ((el.textContent || '').includes('touch ')) return true;
          }
        }
        return false;
      })()`);
      if (!insertedViaExec) {
        await cdp.send("Input.insertText", { text: prompt });
      }
      await sleep(250);
      await cdp.key("Enter", "Enter", 13, 0);
      await sleep(400);
      // If editor still holds our prompt text (e.g. Enter didn't submit), click the submit arrow button inside .full-input-box.
      const submitBtn = await cdp.eval(`(() => {
        const boxEl = document.querySelector('.ai-input-full-input-box, .full-input-box');
        if (!boxEl) return null;
        const ed = boxEl.querySelector('[contenteditable="true"]');
        if (!ed || !(ed.textContent || '').includes('touch ')) return null;
        const btns = [...boxEl.querySelectorAll('button, [role="button"], .anysphere-icon-button, .codicon-arrow-up, .codicon-send')];
        const vis = btns.filter(b => {
          const r = b.getBoundingClientRect();
          const aria = (b.getAttribute('aria-label') || b.getAttribute('title') || '').toLowerCase();
          const cls = String(b.className || '');
          return r.width > 10 && r.height > 10 && (aria.includes('send') || aria.includes('submit') || cls.includes('arrow-up') || cls.includes('send'));
        });
        const target = vis[vis.length - 1];
        if (!target) return null;
        const r = target.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (submitBtn) {
        await cdp.click(submitBtn.x, submitBtn.y);
      }
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
  } catch (err) {
    if (cdp) {
      const diag = await cdp.eval(`(() => {
        const box = document.querySelector('.ai-input-full-input-box, .full-input-box');
        const ed = box ? box.querySelector('[contenteditable="true"]') : null;
        const btns = [...document.querySelectorAll('button, [role="button"]')].map(b => (b.textContent || '').replace(/\\s+/g, ' ').trim()).filter(Boolean).slice(0, 30);
        return {
          title: document.title,
          hasWsInDom: Boolean(document.body && document.body.innerText.includes(${JSON.stringify(path.basename(ws))})),
          editorRemains: ed ? (ed.textContent || '').slice(0, 120) : null,
          buttons: btns,
          tailText: document.body ? document.body.innerText.replace(/\\s+/g, ' ').slice(-500) : null,
        };
      })()`).catch(() => null);
      if (diag) console.error("  [cursor-diag]", JSON.stringify(diag));
    }
    throw err;
  } finally {
    if (cdp) cdp.close();
    if (launchedViaOpen) {
      spawnSync("osascript", ["-e", 'tell application "Cursor" to quit']);
      await sleep(1000);
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
    const claudeRunning =
      spawnSync("pgrep", ["-f", "/Applications/Claude.app/Contents/MacOS/Claude"]).status === 0;
    if (!claudeRunning) {
      spawnSync("open", ["-a", "Claude"]);
      axRun(axBin, ["wait-ready", "Claude", "30"]);
      await sleep(1500);
    } else {
      const dismissed = axRun(axBin, ["dismiss-stale-trust"]).stdout;
      if (dismissed === "dismissed") await sleep(800);
    }
    spawnSync("open", ["-a", "Claude", "-u", `claude://code/new?folder=${ws}&source=services`]);
    await sleep(2000);
    try {
      axRun(axBin, ["wait-ready", "Claude", "15", path.basename(ws)]);
    } catch {
      axRun(axBin, ["dismiss-stale-trust"]);
      await sleep(600);
      spawnSync("open", ["-a", "Claude", "-u", `claude://code/new?folder=${ws}&source=services`]);
      await sleep(2000);
      axRun(axBin, ["wait-ready", "Claude", "25", path.basename(ws)]);
    }
  } else {
    axRun(axBin, ["wait-ready", "Claude", "35", path.basename(ws)]);
  }
  const modelOut = axRun(axBin, ["claude-haiku"]).stdout;
  if (modelOut) {
    console.log(`  Claude temporary profile: ${modelOut}`);
  }

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
    const base = path.basename(file);
    console.log("\n#3 ASK-CD-ONCE");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Allow once", "35", base]);
    await waitUntil(() => existsSync(file) && hasLogged(file, "human:allow"), 35000, 250, "ASK-CD-ONCE step 1");
    await sleep(settleMs);
    rmSync(file, { force: true });
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Deny", "35", base]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-ONCE step 2");
    await sleep(settleMs);
    assertChecks(3, "ASK-CD-ONCE", file, ["no marker", "log human:allow", "log human:deny"]);
  }

  // Row 4: ASK-CD-SESSION
  {
    const file = path.join(ws, "ASK-CD-SESSION-1.marker");
    const base = path.basename(file);
    console.log("\n#4 ASK-CD-SESSION");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Allow this session", "35", base]);
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
    const base = path.basename(file);
    console.log("\n#5 ASK-CD-REJECT");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Deny", "35", base]);
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
    const base = path.basename(file);
    console.log("\n#6 ASK-CD-EXPLAIN");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Explain", "35", base]);
    const waitRes = axRun(axBin, ["wait-explained", "Claude", base, "50"]);
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
      !badError &&
      (hasExplanation ||
        texts.some(
          (t) =>
            t.trim().split(/\s+/).length >= 5 &&
            !t.includes("Use the shell tool") &&
            !t.startsWith("yolonot: rule ") &&
            !t.startsWith("$ touch ")
        ));
    axRun(axBin, ["choose-ask", "Claude", "Deny", "25", base]);
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
    const base = path.basename(file);
    console.log("\n#7 ASK-CD-ESC");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["esc-ask", "Claude", "35", base]);
    await sleep(settleMs);
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Deny", "35", base]);
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
    const base = path.basename(file);
    console.log("\n#10 ASK-CD-AUTO");
    axRun(axBin, ["send-prompt", "Claude", buildPrompt(file)]);
    axRun(axBin, ["choose-ask", "Claude", "Deny", "35", base]);
    await waitUntil(() => hasLogged(file, "human:deny"), 35000, 250, "ASK-CD-AUTO");
    await sleep(settleMs);
    assertChecks(10, "ASK-CD-AUTO", file, ["no marker", "log human:deny"]);
  }
}

async function runCodexDesktopSignoff() {
  const testCdpBase = process.env.YOLONOT_CODEX_CDP_URL || "";
  let cdpBase = testCdpBase;
  let launchedViaOpen = false;
  let wasRunning = false;

  let targetProfile = { model: "", reasoning_effort: "low" };
  const modelJsonPath = path.join(tmpDir, "codex-model.json");
  if (existsSync(modelJsonPath)) {
    try {
      targetProfile = JSON.parse(readFileSync(modelJsonPath, "utf8"));
    } catch {}
  }

  const chatgptPattern = "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT";
  if (!cdpBase) {
    if (!existsSync("/Applications/ChatGPT.app")) {
      console.error("ChatGPT.app not found at /Applications/ChatGPT.app");
      process.exit(75);
    }
    wasRunning = spawnSync("pgrep", ["-f", chatgptPattern]).status === 0;
    if (wasRunning) {
      console.log("  Quitting running ChatGPT/Codex instance so hooks & low-model config reload...");
      spawnSync("pkill", ["-TERM", "-f", chatgptPattern]);
      await waitUntil(
        () => spawnSync("pgrep", ["-f", chatgptPattern]).status !== 0,
        15000,
        300,
        "ChatGPT to quit"
      );
    }
    const port = await freePort();
    cdpBase = `http://127.0.0.1:${port}`;
    spawnSync("open", ["-a", "ChatGPT", "--args", `--remote-debugging-port=${port}`]);
    launchedViaOpen = true;
  }

  let cdp = null;
  try {
    const listCodexPages = async () => {
      try {
        const resp = await fetch(`${cdpBase}/json/list`);
        if (!resp.ok) return [];
        const pages = await resp.json();
        return pages.filter(
          (p) => p.type === "page" && p.webSocketDebuggerUrl && !String(p.url).startsWith("devtools://")
        );
      } catch {
        return [];
      }
    };

    let pages = await waitUntil(
      async () => {
        const p = await listCodexPages();
        return p.length ? p : null;
      },
      30000,
      400,
      "Codex Desktop CDP page target"
    );

    const wsBase = path.basename(ws);
    let currentWsUrl = "";
    const ensureCodexCdp = async () => {
      if (cdp && cdp.isOpen()) return;
      const freshPages = await waitUntil(
        async () => {
          const p = await listCodexPages();
          return p.length ? p : null;
        },
        20000,
        400,
        "Codex Desktop active CDP page"
      );
      const nextTarget =
        freshPages.find((p) => String(p.title || "").includes(wsBase) || String(p.url || "").includes("codex")) ||
        freshPages[0];
      if (cdp) cdp.close();
      currentWsUrl = nextTarget.webSocketDebuggerUrl;
      cdp = new CDPClient(currentWsUrl);
      await cdp.connect();
      await cdp.send("Runtime.enable");
    };

    await ensureCodexCdp();

    const findCodexComposer = async () => {
      await ensureCodexCdp();
      return cdp.eval(`(() => {
        const selectors = [
          '[data-codex-composer-root] [data-composer-markdown][contenteditable="true"]',
          '[data-codex-composer-root] .ProseMirror[contenteditable="true"]',
          '[data-composer-markdown][contenteditable="true"]',
          '.ProseMirror[role="textbox"][contenteditable="true"]',
          '[data-codex-composer-root] textarea',
        ];
        for (const sel of selectors) {
          for (const el of document.querySelectorAll(sel)) {
            const r = el.getBoundingClientRect();
            const st = window.getComputedStyle(el);
            if (r.width > 60 && r.height > 10 && st.visibility !== 'hidden' && st.display !== 'none') {
              return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
            }
          }
        }
        return null;
      })()`).catch(() => null);
    };

    await waitUntil(findCodexComposer, 30000, 400, "Codex Desktop composer input");
    await sleep(settleMs);

    // Send codex://new?path=<ws> AFTER the React shell has mounted and wait
    // until [data-codex-composer-root]'s project control actually switches to <wsBase>.
    if (!testCdpBase) {
      // Allow Codex's embedded app-server IPC to finish initializing before sending codex://new.
      await sleep(3000);
      let poll = 0;
      await waitUntil(
        async () => {
          if (poll % 12 === 0) {
            spawnSync("open", ["-a", "ChatGPT", `codex://new?path=${ws}`]);
          }
          poll++;
          const freshPages = await listCodexPages();
          const wsPage = freshPages.find((p) => String(p.title || "").includes(wsBase));
          if (wsPage && wsPage.webSocketDebuggerUrl !== currentWsUrl) {
            if (cdp) cdp.close();
            currentWsUrl = wsPage.webSocketDebuggerUrl;
            cdp = new CDPClient(currentWsUrl);
            await cdp.connect();
            await cdp.send("Runtime.enable");
          }
          await ensureCodexCdp();
          return cdp
            .eval(`(() => {
              const root = document.querySelector('[data-codex-composer-root]');
              if (!root) return false;
              const btns = [...root.querySelectorAll('button, [role="button"]')].map(b => (b.textContent || '').replace(/\\s+/g, ' ').trim());
              return btns.some(t => t.includes(${JSON.stringify(wsBase)}));
            })()`)
            .catch(() => false);
        },
        30000,
        350,
        `Codex thread bound to ${wsBase}`
      );
      await sleep(1000);
    }
    console.log(`  Connected to Codex Desktop workspace thread: ${wsBase}`);

    // Helper to click a menu option in an open popover/dropdown by regex.
    async function selectDropdownOption(patternSource, flags = "i") {
      const pt = await cdp.eval(`(() => {
        const rx = new RegExp(${JSON.stringify(patternSource)}, ${JSON.stringify(flags)});
        const items = [...document.querySelectorAll('[role="menuitem"], [role="menuitemradio"], [role="option"], [data-radix-collection-item], button, div[tabindex]')];
        const hits = items.filter(el => {
          const r = el.getBoundingClientRect();
          const st = window.getComputedStyle(el);
          if (r.width < 20 || r.height < 12 || r.height > 70 || st.visibility === 'hidden' || st.display === 'none') return false;
          const t = (el.textContent || '').replace(/\\s+/g, ' ').trim();
          return rx.test(t);
        });
        if (!hits.length) return null;
        // Prefer shortest label match so "Low" wins over longer descriptions.
        hits.sort((a, b) => (a.textContent || '').trim().length - (b.textContent || '').trim().length);
        const r = hits[0].getBoundingClientRect();
        return { text: (hits[0].textContent || '').replace(/\\s+/g, ' ').trim(), x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (pt) {
        await cdp.click(pt.x, pt.y);
        await sleep(300);
        return pt.text;
      }
      await cdp.key("Escape", "Escape", 27, 0);
      await sleep(150);
      return null;
    }

    // Configure Composer utility bar:
    // 1) Approval mode = "Ask for approval" (never "Approve for me" / "Full access")
    // 2) Model = lowest model (e.g. gpt-5.6-luna / mini)
    // 3) Reasoning effort = lowest effort (Low / Minimal)
    async function configureCodexSessionBar() {
      // 1) Approval picker
      const approvalBtn = await cdp.eval(`(() => {
        const btns = [...document.querySelectorAll('button, [role="button"]')];
        const hit = btns.find(b => {
          const t = (b.textContent || '').replace(/\\s+/g, ' ').trim();
          const r = b.getBoundingClientRect();
          return r.width > 20 && r.height > 12 && /^(Approve for me|Full access|Agent \\(full access\\)|Auto-approve)/i.test(t);
        });
        if (!hit) return null;
        const r = hit.getBoundingClientRect();
        return { text: (hit.textContent || '').trim(), x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (approvalBtn) {
        await cdp.click(approvalBtn.x, approvalBtn.y);
        await sleep(350);
        await selectDropdownOption("^(Ask for approval|Suggest|Default permissions)", "i");
      }

      // 2) Model picker (if UI shows a heavier model than targetProfile.model)
      if (targetProfile.model) {
        const wantModel = targetProfile.model;
        const modelBtn = await cdp.eval(`(() => {
          const root = document.querySelector('[data-codex-composer-root]') || document.body;
          const btns = [...root.querySelectorAll('button, [role="button"]')];
          const hit = btns.find(b => {
            const t = (b.textContent || '').replace(/\\s+/g, ' ').trim();
            const r = b.getBoundingClientRect();
            return r.width > 20 && r.height > 12 && /(gpt-|codex|o[134]-|luna|terra)/i.test(t);
          });
          if (!hit) return null;
          const r = hit.getBoundingClientRect();
          return { text: (hit.textContent || '').replace(/\\s+/g, ' ').trim(), x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`);
        if (modelBtn && !modelBtn.text.toLowerCase().includes(wantModel.toLowerCase())) {
          await cdp.click(modelBtn.x, modelBtn.y);
          await sleep(350);
          const escaped = wantModel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          await selectDropdownOption(escaped, "i");
        }
      }

      // 3) Reasoning effort picker (if UI shows Medium / High / Extra high / Max / Ultra)
      const effortBtn = await cdp.eval(`(() => {
        const root = document.querySelector('[data-codex-composer-root]') || document.body;
        const btns = [...root.querySelectorAll('button, [role="button"]')];
        const hit = btns.find(b => {
          const t = (b.textContent || '').replace(/\\s+/g, ' ').trim();
          const r = b.getBoundingClientRect();
          return r.width > 16 && r.height > 12 && /^(Medium|High|Extra high|X-High|xhigh|Max|Ultra)$/i.test(t);
        });
        if (!hit) return null;
        const r = hit.getBoundingClientRect();
        return { text: (hit.textContent || '').replace(/\\s+/g, ' ').trim(), x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (effortBtn) {
        await cdp.click(effortBtn.x, effortBtn.y);
        await sleep(350);
        await selectDropdownOption("^(Minimal|Low)\\b", "i");
      }

      const barPills = await cdp.eval(`(() => {
        const root = document.querySelector('[data-codex-composer-root]') || document.body;
        return [...root.querySelectorAll('button, [role="button"]')]
          .map(b => (b.textContent || '').replace(/\\s+/g, ' ').trim())
          .filter(Boolean)
          .slice(0, 15);
      })()`);
      console.log(`  Codex composer controls: ${JSON.stringify(barPills)}`);
    }

    await configureCodexSessionBar();

    async function findApprovalRequest() {
      return cdp.eval(`(() => {
        const visible = (el) => {
          if (!el) return false;
          const r = el.getBoundingClientRect();
          const st = window.getComputedStyle(el);
          return r.width > 8 && r.height > 8 && st.visibility !== 'hidden' && st.display !== 'none';
        };
        const reqCard = document.querySelector('[data-codex-composer-request]');
        const scope = (reqCard && visible(reqCard)) ? reqCard : document.body;
        const btns = [...scope.querySelectorAll('button, [role="button"]')].filter(visible);
        const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim();
        // Single-command approve button (exclude "Allow for this session" / "Always" so Row #5 repeats!)
        // Note: Codex concatenates keycap badges in textContent, e.g. "Allow once⏎" and "DenyEsc".
        const approveBtns = btns.filter(b => {
          const t = norm(b.textContent);
          if (/session|always|for me|full access/i.test(t)) return false;
          return /^(Allow once|Yes\\b|Yes⏎|Approve|Allow\\b|Allow⏎|Run\\b|Run⏎)/i.test(t);
        });
        const rejectBtns = btns.filter(b => {
          const t = norm(b.textContent);
          return /^(Deny|Decline|Reject|No\\b|No,|NoEsc|Skip|Cancel)/i.test(t) || /continue without/i.test(t);
        });
        if (!reqCard && (!approveBtns.length || !rejectBtns.length)) return null;
        if (reqCard && !approveBtns.length && !rejectBtns.length) return null;
        approveBtns.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
        rejectBtns.sort((a, b) => b.getBoundingClientRect().top - a.getBoundingClientRect().top);
        const rectOf = (el) => {
          if (!el) return null;
          const r = el.getBoundingClientRect();
          return { text: norm(el.textContent), x: r.left + r.width / 2, y: r.top + r.height / 2 };
        };
        return {
          hasCard: true,
          approve: rectOf(approveBtns[0]),
          reject: rectOf(rejectBtns[0]),
          allButtons: btns.map(b => norm(b.textContent)).filter(Boolean).slice(0, 12),
        };
      })()`);
    }

    async function sendCodexPrompt(prompt) {
      const box = await waitUntil(findCodexComposer, 20000, 300, "Codex composer input");
      await cdp.click(box.x, box.y);
      await sleep(120);
      await cdp.key("a", "KeyA", 65, 4);
      await sleep(50);
      await cdp.key("Backspace", "Backspace", 8, 0);
      await sleep(80);
      const inserted = await cdp.eval(`(() => {
        const selectors = [
          '[data-codex-composer-root] [data-composer-markdown][contenteditable="true"]',
          '[data-codex-composer-root] .ProseMirror[contenteditable="true"]',
          '[data-composer-markdown][contenteditable="true"]',
          '.ProseMirror[role="textbox"][contenteditable="true"]',
        ];
        for (const sel of selectors) {
          const el = document.querySelector(sel);
          if (el) {
            el.focus();
            document.execCommand('selectAll', false, null);
            document.execCommand('insertText', false, ${JSON.stringify(prompt)});
            if ((el.textContent || '').includes('touch ')) return true;
          }
        }
        return false;
      })()`);
      if (!inserted) {
        await cdp.send("Input.insertText", { text: prompt });
      }
      await sleep(220);
      await cdp.key("Enter", "Enter", 13, 0);
      await sleep(350);
      // Fallback submit button inside [data-codex-composer-root] if text is still in editor.
      const submitPt = await cdp.eval(`(() => {
        const root = document.querySelector('[data-codex-composer-root]');
        if (!root) return null;
        const ed = root.querySelector('[contenteditable="true"], textarea');
        const txt = ed ? (ed.value || ed.textContent || '') : '';
        if (!txt.includes('touch ')) return null;
        const btns = [...root.querySelectorAll('button:not([disabled])')];
        const hit = btns.find(b => {
          const aria = (b.getAttribute('aria-label') || b.getAttribute('title') || '').toLowerCase();
          return aria.includes('send') || aria.includes('submit');
        }) || btns[btns.length - 1];
        if (!hit) return null;
        const r = hit.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`);
      if (submitPt) {
        await cdp.click(submitPt.x, submitPt.y);
      }
    }

    // Row 1: ALLOW-CX
    {
      const file = path.join(ws, "ALLOW-CX-1.marker");
      console.log("\n#1 ALLOW-CX");
      let sawUnexpectedCard = false;
      await sendCodexPrompt(buildPrompt(file, true));
      await waitUntil(
        async () => {
          if (await findApprovalRequest()) sawUnexpectedCard = true;
          return existsSync(file) && hasLogged(file, "rule:allow");
        },
        60000,
        250,
        "ALLOW-CX marker + rule:allow"
      );
      await sleep(settleMs);
      assertChecks(
        1,
        "ALLOW-CX",
        file,
        ["marker", "log rule:allow", "see: The command ran without an approval request in the chat?"],
        { "see: The command ran without an approval request in the chat?": !sawUnexpectedCard }
      );
    }

    // Row 2: DENY-CX
    {
      const file = path.join(ws, "DENY-CX-1.marker");
      console.log("\n#2 DENY-CX");
      await sendCodexPrompt(buildPrompt(file, true));
      await waitUntil(() => hasLogged(file, "rule:deny"), 60000, 250, "DENY-CX rule:deny");
      await sleep(settleMs);
      assertChecks(2, "DENY-CX", file, ["no marker", "log rule:deny"]);
    }

    // Row 3: ASK-CX-APPROVE
    {
      const file = path.join(ws, "ASK-CX-APPROVE-1.marker");
      console.log("\n#3 ASK-CX-APPROVE");
      await sendCodexPrompt(buildPrompt(file, true));
      await waitUntil(() => hasLogged(file, "rule:ask"), 60000, 250, "ASK-CX-APPROVE rule:ask");
      const card = await waitUntil(findApprovalRequest, 35000, 250, "ASK-CX-APPROVE approval request");
      const waitedBeforeMarker = Boolean(card?.hasCard) && !existsSync(file);
      if (card.approve) await cdp.click(card.approve.x, card.approve.y);
      else await cdp.key("Enter", "Enter", 13, 0);
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
      await sendCodexPrompt(buildPrompt(file, true));
      await waitUntil(() => hasLogged(file, "rule:ask"), 60000, 250, "ASK-CX-REJECT rule:ask");
      const card = await waitUntil(findApprovalRequest, 35000, 250, "ASK-CX-REJECT approval request");
      if (card.reject) await cdp.click(card.reject.x, card.reject.y);
      else await cdp.key("Escape", "Escape", 27, 0);
      await sleep(settleMs);
      assertChecks(4, "ASK-CX-REJECT", file, ["no marker", "log rule:ask", "no log human:allow"]);
    }

    // Row 5: ASK-CX-REPEAT
    {
      const file = path.join(ws, "ASK-CX-REPEAT-1.marker");
      console.log("\n#5 ASK-CX-REPEAT");
      await sendCodexPrompt(buildPrompt(file, true));
      const card1 = await waitUntil(findApprovalRequest, 60000, 250, "ASK-CX-REPEAT step 1 approval");
      if (card1.approve) await cdp.click(card1.approve.x, card1.approve.y);
      else await cdp.key("Enter", "Enter", 13, 0);
      await waitUntil(() => existsSync(file), 35000, 250, "ASK-CX-REPEAT step 1 marker");
      await sleep(settleMs);
      rmSync(file, { force: true });

      await sendCodexPrompt(buildPrompt(file, true));
      const card2 = await waitUntil(findApprovalRequest, 60000, 250, "ASK-CX-REPEAT step 2 approval");
      const waitedAgain = Boolean(card2?.hasCard) && !existsSync(file);
      if (card2.approve) await cdp.click(card2.approve.x, card2.approve.y);
      else await cdp.key("Enter", "Enter", 13, 0);
      await waitUntil(() => existsSync(file), 35000, 250, "ASK-CX-REPEAT step 2 marker");
      await sleep(settleMs);
      assertChecks(
        5,
        "ASK-CX-REPEAT",
        file,
        ["marker", "see: The repeat asked for approval again?"],
        { "see: The repeat asked for approval again?": waitedAgain }
      );
    }
  } catch (err) {
    if (cdp) {
      const diag = await cdp.eval(`(() => {
        const root = document.querySelector('[data-codex-composer-root]');
        const req = document.querySelector('[data-codex-composer-request]');
        return {
          hasReqCard: Boolean(req),
          reqButtons: req ? [...req.querySelectorAll('button, [role="button"]')].map(b => (b.textContent || '').replace(/\\s+/g, ' ').trim()).filter(Boolean) : [],
          composerButtons: root ? [...root.querySelectorAll('button, [role="button"]')].map(b => (b.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 60)).filter(Boolean) : [],
        };
      })()`).catch(() => null);
      if (diag) console.error("  [codex-diag]", JSON.stringify(diag));
    }
    throw err;
  } finally {
    if (cdp) cdp.close();
    if (launchedViaOpen) {
      spawnSync("pkill", ["-TERM", "-f", chatgptPattern]);
      await sleep(1000);
    }
    if (!testCdpBase && wasRunning) {
      spawn("open", ["-g", "-a", "ChatGPT"], { stdio: "ignore", detached: true }).unref();
    }
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
