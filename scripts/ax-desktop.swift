import AppKit
import ApplicationServices
import Foundation

// Native macOS Accessibility helper for hands-free desktop sign-off
// (Claude Desktop & Codex Desktop). Enables Chromium/Electron's lazy
// accessibility tree via AXManualAccessibility and drives UI elements
// without binary patching or unsupported debug flags.

struct ElemInfo: Codable {
    let role: String
    let subrole: String
    let title: String
    let desc: String
    let value: String
    let x: Double
    let y: Double
    let w: Double
    let h: Double
    let actions: [String]
    let editable: Bool
    let focused: Bool
}

struct CollectedElem {
    let ref: AXUIElement
    let info: ElemInfo
}

func strAttr(_ el: AXUIElement, _ attr: String) -> String {
    var val: CFTypeRef?
    let err = AXUIElementCopyAttributeValue(el, attr as CFString, &val)
    guard err == .success, let v = val else { return "" }
    if let s = v as? String { return s }
    if let n = v as? NSNumber { return n.stringValue }
    return ""
}

func boolAttr(_ el: AXUIElement, _ attr: String) -> Bool {
    var val: CFTypeRef?
    let err = AXUIElementCopyAttributeValue(el, attr as CFString, &val)
    guard err == .success, let v = val else { return false }
    if let b = v as? Bool { return b }
    if let n = v as? NSNumber { return n.boolValue }
    return false
}

func isSettable(_ el: AXUIElement, _ attr: String) -> Bool {
    var settable = DarwinBoolean(false)
    let err = AXUIElementIsAttributeSettable(el, attr as CFString, &settable)
    return err == .success && settable.boolValue
}

func frameAttr(_ el: AXUIElement) -> (Double, Double, Double, Double) {
    var posRef: CFTypeRef?
    var sizeRef: CFTypeRef?
    var pt = CGPoint.zero
    var sz = CGSize.zero
    if AXUIElementCopyAttributeValue(el, kAXPositionAttribute as CFString, &posRef) == .success,
       let pv = posRef, CFGetTypeID(pv) == AXValueGetTypeID() {
        AXValueGetValue(pv as! AXValue, .cgPoint, &pt)
    }
    if AXUIElementCopyAttributeValue(el, kAXSizeAttribute as CFString, &sizeRef) == .success,
       let sv = sizeRef, CFGetTypeID(sv) == AXValueGetTypeID() {
        AXValueGetValue(sv as! AXValue, .cgSize, &sz)
    }
    return (Double(pt.x), Double(pt.y), Double(sz.width), Double(sz.height))
}

func actionsOf(_ el: AXUIElement) -> [String] {
    var names: CFArray?
    guard AXUIElementCopyActionNames(el, &names) == .success,
          let arr = names as? [String] else { return [] }
    return arr
}

func childrenOf(_ el: AXUIElement) -> [AXUIElement] {
    var out: [AXUIElement] = []
    for attr in [kAXChildrenAttribute as String, "AXVisibleChildren", "AXContents"] {
        var val: CFTypeRef?
        if AXUIElementCopyAttributeValue(el, attr as CFString, &val) == .success,
           let arr = val as? [AXUIElement], !arr.isEmpty {
            out.append(contentsOf: arr)
            break
        }
    }
    return out
}

func runningApp(_ name: String) -> NSRunningApplication? {
    let ws = NSWorkspace.shared.runningApplications
    if let exact = ws.first(where: { $0.localizedName == name && !$0.isTerminated }) {
        return exact
    }
    return ws.first(where: {
        ($0.bundleURL?.deletingPathExtension().lastPathComponent == name) && !$0.isTerminated
    })
}

func enableAccessibility(_ appRef: AXUIElement) {
    _ = AXUIElementSetAttributeValue(appRef, "AXManualAccessibility" as CFString, kCFBooleanTrue)
    _ = AXUIElementSetAttributeValue(appRef, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
}

func targetWindow(_ appRef: AXUIElement) -> AXUIElement? {
    var winVal: CFTypeRef?
    if AXUIElementCopyAttributeValue(appRef, kAXFocusedWindowAttribute as CFString, &winVal) == .success,
       let w = winVal {
        return (w as! AXUIElement)
    }
    if AXUIElementCopyAttributeValue(appRef, kAXMainWindowAttribute as CFString, &winVal) == .success,
       let w = winVal {
        return (w as! AXUIElement)
    }
    var listVal: CFTypeRef?
    if AXUIElementCopyAttributeValue(appRef, kAXWindowsAttribute as CFString, &listVal) == .success,
       let arr = listVal as? [AXUIElement], let first = arr.first {
        return first
    }
    return nil
}

func collectTree(_ root: AXUIElement, maxNodes: Int = 4000) -> [CollectedElem] {
    var results: [CollectedElem] = []
    var queue: [AXUIElement] = [root]
    var visited = Set<CFHashCode>()
    var idx = 0
    while idx < queue.count && results.count < maxNodes {
        let cur = queue[idx]
        idx += 1
        let h = CFHash(cur)
        if visited.contains(h) { continue }
        visited.insert(h)

        let role = strAttr(cur, kAXRoleAttribute as String)
        let subrole = strAttr(cur, kAXSubroleAttribute as String)
        let title = strAttr(cur, kAXTitleAttribute as String)
        let desc = strAttr(cur, kAXDescriptionAttribute as String)
        let value = strAttr(cur, kAXValueAttribute as String)
        let (x, y, w, ht) = frameAttr(cur)
        let acts = actionsOf(cur)
        let editable = boolAttr(cur, "AXEditable") || (
            (role == "AXTextArea" || role == "AXTextField") && isSettable(cur, kAXValueAttribute as String)
        )
        let focused = boolAttr(cur, kAXFocusedAttribute as String)

        results.append(CollectedElem(
            ref: cur,
            info: ElemInfo(
                role: role, subrole: subrole, title: title, desc: desc,
                value: String(value.prefix(1000)),
                x: x, y: y, w: w, h: ht,
                actions: acts, editable: editable, focused: focused
            )
        ))
        for ch in childrenOf(cur) {
            queue.append(ch)
        }
    }
    return results
}

func clickPoint(_ x: Double, _ y: Double) {
    let pt = CGPoint(x: x, y: y)
    if let move = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: pt, mouseButton: .left) {
        move.post(tap: .cghidEventTap)
    }
    Thread.sleep(forTimeInterval: 0.04)
    if let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: pt, mouseButton: .left),
       let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: pt, mouseButton: .left) {
        down.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.04)
        up.post(tap: .cghidEventTap)
    }
}

func sendKey(_ keyCode: CGKeyCode, flags: CGEventFlags = []) {
    guard let src = CGEventSource(stateID: .hidSystemState),
          let down = CGEvent(keyboardEventSource: src, virtualKey: keyCode, keyDown: true),
          let up = CGEvent(keyboardEventSource: src, virtualKey: keyCode, keyDown: false) else { return }
    down.flags = flags
    up.flags = flags
    down.post(tap: .cghidEventTap)
    Thread.sleep(forTimeInterval: 0.04)
    up.post(tap: .cghidEventTap)
}

func activateApp(_ app: NSRunningApplication) {
    _ = app.activate(options: [.activateAllWindows])
    Thread.sleep(forTimeInterval: 0.20)
}

func pressElement(_ item: CollectedElem) {
    if item.info.actions.contains(kAXPressAction as String) {
        if AXUIElementPerformAction(item.ref, kAXPressAction as CFString) == .success {
            return
        }
    }
    if item.info.w > 2 && item.info.h > 2 {
        clickPoint(item.info.x + item.info.w / 2.0, item.info.y + item.info.h / 2.0)
    }
}

func elementLabels(_ e: ElemInfo) -> [String] {
    return [e.title, e.desc, e.value]
        .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        .filter { !$0.isEmpty }
}

func findComposer(_ nodes: [CollectedElem]) -> CollectedElem? {
    let candidates = nodes.filter { n in
        guard n.info.w > 80 && n.info.h > 12 else { return false }
        if n.info.editable { return true }
        if n.info.role == "AXTextArea" || n.info.role == "AXTextField" { return true }
        return false
    }
    // Prefer the bottommost editable input in the window (the main chat composer).
    return candidates.max(by: { $0.info.y < $1.info.y })
}

func detectClaudeMode(_ nodes: [CollectedElem]) -> String {
    // Claude Desktop 5.x mode pill labels: "Manual" (default), "Accept edits",
    // "Plan", "Auto", "Bypass permissions", "Don't ask" (plus "Ask permissions" in older builds).
    let modeMap: [(needle: String, canonical: String)] = [
        ("Bypass permissions", "bypass"),
        ("Accept edits", "acceptEdits"),
        ("Ask permissions", "default"),
        ("Don't ask", "dontAsk"),
        ("Manual", "default"),
        ("Auto mode", "auto"),
        ("Plan mode", "plan"),
        ("Auto", "auto"),
        ("Plan", "plan"),
    ]
    // Look at buttons / static texts near the bottom half of the window (composer toolbar).
    let maxY = nodes.map { $0.info.y + $0.info.h }.max() ?? 1000.0
    let toolbarNodes = nodes.filter { $0.info.w > 4 && $0.info.h > 4 && $0.info.y >= maxY * 0.45 }
    for (needle, canonical) in modeMap {
        for n in toolbarNodes {
            for lbl in elementLabels(n.info) {
                if lbl.caseInsensitiveCompare(needle) == .orderedSame ||
                   lbl.lowercased().hasPrefix(needle.lowercased() + " ") ||
                   lbl.lowercased().hasSuffix(" " + needle.lowercased()) {
                    return canonical
                }
            }
        }
    }
    return "default"
}

func findClickableText(_ nodes: [CollectedElem], target: String, exact: Bool) -> CollectedElem? {
    let norm = target.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    let actionableRoles: Set<String> = ["AXButton", "AXRadioButton", "AXCheckBox", "AXMenuItem", "AXPopUpButton", "AXLink"]

    let matches = nodes.filter { n in
        guard n.info.w > 2 && n.info.h > 2 else { return false }
        let labels = elementLabels(n.info)
        return labels.contains { raw in
            let l = raw.lowercased()
            if exact {
                return l == norm || l.hasPrefix(norm + "\n") || l.hasPrefix("1. " + norm) || l.hasPrefix("2. " + norm) || l.hasPrefix("3. " + norm) || l.hasPrefix("4. " + norm)
            }
            return l.contains(norm)
        }
    }
    if matches.isEmpty { return nil }

    // Prefer actionable controls lowest in the chat viewport (newest dialog card).
    let actionable = matches.filter {
        actionableRoles.contains($0.info.role) || $0.info.actions.contains(kAXPressAction as String)
    }
    if let best = actionable.max(by: { $0.info.y < $1.info.y }) {
        return best
    }
    return matches.max(by: { $0.info.y < $1.info.y })
}

// MARK: - CLI Dispatch

let args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else {
    fputs("usage: ax-desktop <check|tree|wait-ready|claude-mode|send-prompt|click-text|wait-text|key> ...\n", stderr)
    exit(2)
}

if cmd == "check" {
    let prompt = args.contains("--prompt")
    let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt] as CFDictionary
    if AXIsProcessTrustedWithOptions(opts) {
        print("trusted")
        exit(0)
    } else {
        fputs("Accessibility permission is not granted for this terminal.\n", stderr)
        exit(75)
    }
}

guard AXIsProcessTrusted() else {
    fputs("Accessibility permission is not granted.\n", stderr)
    exit(75)
}

func requireWindow(_ appName: String, timeoutSec: Double = 20.0) -> (NSRunningApplication, AXUIElement, AXUIElement) {
    let deadline = Date().addingTimeInterval(timeoutSec)
    while Date() < deadline {
        if let app = runningApp(appName) {
            let appRef = AXUIElementCreateApplication(app.processIdentifier)
            enableAccessibility(appRef)
            if let win = targetWindow(appRef) {
                return (app, appRef, win)
            }
            activateApp(app)
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    fputs("Timed out waiting for \(appName) window.\n", stderr)
    exit(1)
}

switch cmd {
case "tree":
    guard args.count >= 2 else { exit(2) }
    let (app, _, win) = requireWindow(args[1])
    activateApp(app)
    Thread.sleep(forTimeInterval: 0.4)
    let nodes = collectTree(win).map { $0.info }.filter {
        !$0.title.isEmpty || !$0.value.isEmpty || !$0.desc.isEmpty || $0.editable
    }
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted]
    if let data = try? enc.encode(nodes), let s = String(data: data, encoding: .utf8) {
        print(s)
    }

case "wait-ready":
    guard args.count >= 2 else { exit(2) }
    let appName = args[1]
    let timeout = args.count >= 3 ? (Double(args[2]) ?? 25.0) : 25.0
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let (app, _, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectTree(win)
        if let comp = findComposer(nodes) {
            print("ready:\(comp.info.role):\(Int(comp.info.x)),\(Int(comp.info.y))")
            exit(0)
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
    fputs("Timed out waiting for composer input in \(appName).\n", stderr)
    exit(1)

case "claude-mode":
    guard args.count >= 2 else { exit(2) }
    let want = args[1].lowercased() // "default" or "auto"
    let (app, _, win) = requireWindow("Claude")
    activateApp(app)
    for attempt in 0..<7 {
        let nodes = collectTree(win)
        if let comp = findComposer(nodes), attempt == 0 {
            clickPoint(comp.info.x + comp.info.w / 2.0, comp.info.y + comp.info.h / 2.0)
            Thread.sleep(forTimeInterval: 0.2)
        }
        let cur = detectClaudeMode(nodes)
        if (want == "default" && cur == "default") || (want == "auto" && cur == "auto") {
            print("mode:\(cur)")
            exit(0)
        }
        // Shift+Tab cycles Claude Code permission modes (keyCode 48 = Tab).
        sendKey(48, flags: .maskShift)
        Thread.sleep(forTimeInterval: 0.55)
    }
    let finalMode = detectClaudeMode(collectTree(win))
    fputs("Failed to switch Claude mode to \(want) (stuck on \(finalMode)).\n", stderr)
    exit(1)

case "send-prompt":
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let promptText = args[2]
    let (app, _, win) = requireWindow(appName)
    activateApp(app)
    let nodes = collectTree(win)
    guard let comp = findComposer(nodes) else {
        fputs("Composer input not found in \(appName).\n", stderr)
        exit(1)
    }
    _ = AXUIElementSetAttributeValue(comp.ref, kAXFocusedAttribute as CFString, kCFBooleanTrue)
    clickPoint(comp.info.x + comp.info.w / 2.0, comp.info.y + comp.info.h / 2.0)
    Thread.sleep(forTimeInterval: 0.20)

    let pb = NSPasteboard.general
    let savedClipboard = pb.string(forType: .string)
    // Select all & replace via clipboard paste so paths/symbols arrive intact.
    sendKey(0, flags: .maskCommand) // Cmd+A (keyCode 0 = 'a')
    Thread.sleep(forTimeInterval: 0.08)
    pb.clearContents()
    pb.setString(promptText, forType: .string)
    Thread.sleep(forTimeInterval: 0.08)
    sendKey(9, flags: .maskCommand) // Cmd+V (keyCode 9 = 'v')
    Thread.sleep(forTimeInterval: 0.25)
    sendKey(36) // Return (keyCode 36)
    Thread.sleep(forTimeInterval: 0.25)
    if let prev = savedClipboard {
        pb.clearContents()
        pb.setString(prev, forType: .string)
    }
    print("sent")

case "click-text":
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let target = args[2]
    let timeout = args.count >= 4 ? (Double(args[3]) ?? 30.0) : 30.0
    let exact = !args.contains("--contains")
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let (app, _, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectTree(win)
        if let hit = findClickableText(nodes, target: target, exact: exact) {
            pressElement(hit)
            print("clicked:\(hit.info.role):\(target)")
            exit(0)
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    fputs("Timed out waiting to click '\(target)' in \(appName).\n", stderr)
    exit(1)

case "wait-text":
    // Waits until `mustAppear` is visible (and optional `--without <gone>` is NOT visible),
    // then prints all visible static/value texts in the bottom half of the window as JSON.
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let mustAppear = args[2].lowercased()
    var mustDisappear: String? = nil
    var timeout = 30.0
    var i = 3
    while i < args.count {
        if args[i] == "--without", i + 1 < args.count {
            mustDisappear = args[i + 1].lowercased()
            i += 2
        } else if args[i] == "--timeout", i + 1 < args.count {
            timeout = Double(args[i + 1]) ?? 30.0
            i += 2
        } else {
            i += 1
        }
    }
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let (app, _, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectTree(win)
        let visibleTexts = nodes.filter { $0.info.w > 1 && $0.info.h > 1 }.flatMap { elementLabels($0.info) }
        let hasTarget = visibleTexts.contains { $0.lowercased().contains(mustAppear) }
        let hasForbidden: Bool = {
            guard let gone = mustDisappear else { return false }
            return findClickableText(nodes, target: gone, exact: true) != nil
        }()
        if hasTarget && !hasForbidden {
            if let data = try? JSONEncoder().encode(visibleTexts), let s = String(data: data, encoding: .utf8) {
                print(s)
            }
            exit(0)
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    fputs("Timed out in wait-text for '\(mustAppear)' in \(appName).\n", stderr)
    exit(1)

case "key":
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let keyName = args[2].lowercased()
    let (app, _, _) = requireWindow(appName)
    activateApp(app)
    switch keyName {
    case "esc", "escape":
        sendKey(53)
    case "enter", "return":
        sendKey(36)
    case "shift-tab":
        sendKey(48, flags: .maskShift)
    default:
        fputs("unknown key \(keyName)\n", stderr)
        exit(2)
    }
    print("key:\(keyName)")

default:
    fputs("unknown subcommand \(cmd)\n", stderr)
    exit(2)
}
