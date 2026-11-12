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
    let selected: Bool
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

func childrenOf(_ el: AXUIElement, checkSheets: Bool = false) -> [AXUIElement] {
    var val: CFTypeRef?
    if AXUIElementCopyAttributeValue(el, kAXChildrenAttribute as CFString, &val) == .success,
       let arr = val as? [AXUIElement], !arr.isEmpty {
        if checkSheets {
            var sheetsVal: CFTypeRef?
            if AXUIElementCopyAttributeValue(el, "AXSheets" as CFString, &sheetsVal) == .success,
               let sheets = sheetsVal as? [AXUIElement], !sheets.isEmpty {
                return sheets + arr
            }
        }
        return arr
    }
    for attr in ["AXVisibleChildren", "AXContents"] {
        var fbVal: CFTypeRef?
        if AXUIElementCopyAttributeValue(el, attr as CFString, &fbVal) == .success,
           let arr = fbVal as? [AXUIElement], !arr.isEmpty {
            return arr
        }
    }
    if checkSheets {
        var sheetsVal: CFTypeRef?
        if AXUIElementCopyAttributeValue(el, "AXSheets" as CFString, &sheetsVal) == .success,
           let sheets = sheetsVal as? [AXUIElement], !sheets.isEmpty {
            return sheets
        }
    }
    return []
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

func allAppWindows(_ appRef: AXUIElement, primary: AXUIElement) -> [AXUIElement] {
    var wins: [AXUIElement] = [primary]
    var seen: Set<CFHashCode> = [CFHash(primary)]
    var listVal: CFTypeRef?
    if AXUIElementCopyAttributeValue(appRef, kAXWindowsAttribute as CFString, &listVal) == .success,
       let arr = listVal as? [AXUIElement] {
        for w in arr {
            let h = CFHash(w)
            if !seen.contains(h) {
                seen.insert(h)
                wins.append(w)
            }
        }
    }
    return wins
}

let interactiveAXRoles: Set<String> = [
    "AXButton", "AXRadioButton", "AXCheckBox", "AXMenuItem",
    "AXPopUpButton", "AXMenuButton", "AXLink", "AXTextArea", "AXTextField", "AXComboBox"
]

func collectWindowNodes(_ appRef: AXUIElement, primary: AXUIElement, maxVisited: Int = 40000) -> [CollectedElem] {
    var roots: [AXUIElement] = []
    // Prepend enclosing ancestor containers (widget -> sheet/toolbar -> active session pane)
    // of the focused UI element so active modals, approval cards ("Submit" + radio options),
    // and composer controls ("Model: ...", "Permissions: ...") are always visited first,
    // even when background sessions or a large session-rail sidebar are mounted.
    var focVal: CFTypeRef?
    if AXUIElementCopyAttributeValue(appRef, kAXFocusedUIElementAttribute as CFString, &focVal) == .success,
       let fv = focVal {
        var cur = fv as! AXUIElement
        var ancestors: [AXUIElement] = [cur]
        for _ in 0..<14 {
            var parentVal: CFTypeRef?
            guard AXUIElementCopyAttributeValue(cur, kAXParentAttribute as CFString, &parentVal) == .success,
                  let pv = parentVal else { break }
            let parent = pv as! AXUIElement
            let pRole = strAttr(parent, kAXRoleAttribute as String)
            if pRole == "AXWindow" || pRole == "AXWebArea" || pRole == "AXApplication" || pRole == "AXUnknown" {
                break
            }
            ancestors.append(parent)
            cur = parent
        }
        for idx in [min(4, ancestors.count - 1), min(8, ancestors.count - 1), ancestors.count - 1] {
            roots.append(ancestors[idx])
        }
    }
    roots.append(contentsOf: allAppWindows(appRef, primary: primary))
    return collectTrees(roots, maxVisited: maxVisited)
}

func collectTree(_ root: AXUIElement, maxVisited: Int = 40000) -> [CollectedElem] {
    return collectTrees([root], maxVisited: maxVisited)
}

func collectTrees(_ roots: [AXUIElement], maxVisited: Int = 40000) -> [CollectedElem] {
    var results: [CollectedElem] = []
    var queue: [AXUIElement] = roots
    var visited = Set<CFHashCode>()
    var idx = 0
    while idx < queue.count && visited.count < maxVisited {
        let cur = queue[idx]
        idx += 1
        let h = CFHash(cur)
        if visited.contains(h) { continue }
        visited.insert(h)

        let role = strAttr(cur, kAXRoleAttribute as String)
        if role == "AXInlineTextBox" {
            continue
        }

        // Skip child traversal only on AXStaticText: in Chromium/Electron, AXStaticText
        // already exposes its full string in AXValue while its AXChildren are 100%
        // AXInlineTextBox glyph boxes (often 70%+ of all nodes in long chats).
        // Enqueue children in reverse DOM order so portals (appended at end of <body>),
        // the right-hand <main> pane (after left <aside> sidebar), the latest session,
        // and the newest bottom chat turn / composer / approval sheet are visited first.
        if role != "AXStaticText" {
            let kids = childrenOf(cur, checkSheets: role == "AXWindow")
            queue.append(contentsOf: kids.reversed())
        }

        let title = strAttr(cur, kAXTitleAttribute as String)
        let desc = strAttr(cur, kAXDescriptionAttribute as String)
        let isInteractive = interactiveAXRoles.contains(role)
        let editable: Bool = {
            if role == "AXTextArea" || role == "AXTextField" || role == "AXComboBox" {
                return boolAttr(cur, "AXEditable") || isSettable(cur, kAXValueAttribute as String)
            }
            if role == "AXGroup" || role == "AXUnknown" || role.isEmpty {
                return boolAttr(cur, "AXEditable")
            }
            return false
        }()
        let skipValue = !editable && (
            role == "AXSplitGroup" || role == "AXScrollArea" ||
            role == "AXWebArea" || role == "AXWindow"
        )
        let value = skipValue ? "" : strAttr(cur, kAXValueAttribute as String)
        let selected = isInteractive ? boolAttr(cur, kAXSelectedAttribute as String) : false

        let keep = isInteractive || editable || selected || !title.isEmpty || !desc.isEmpty || !value.isEmpty
        if keep {
            let subrole = isInteractive ? strAttr(cur, kAXSubroleAttribute as String) : ""
            let focused = (isInteractive || editable) ? boolAttr(cur, kAXFocusedAttribute as String) : false
            let (x, y, w, ht) = frameAttr(cur)
            let acts = (isInteractive || editable || !title.isEmpty || !desc.isEmpty) ? actionsOf(cur) : []
            results.append(CollectedElem(
                ref: cur,
                info: ElemInfo(
                    role: role, subrole: subrole, title: title, desc: desc,
                    value: String(value.prefix(1000)),
                    x: x, y: y, w: w, h: ht,
                    actions: acts, editable: editable, focused: focused, selected: selected
                )
            ))
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

func canonicalModeFromLabel(_ raw: String, allowDescriptionSuffix: Bool = true) -> String? {
    let modeMap: [(needle: String, canonical: String)] = [
        ("bypass permissions", "bypass"),
        ("skip all approvals", "bypass"),
        ("accept edits", "acceptEdits"),
        ("ask permissions", "default"),
        ("manually approve", "default"),
        ("automatically approve", "auto"),
        ("settings default", "settingsDefault"),
        ("don't ask", "dontAsk"),
        ("don’t ask", "dontAsk"),
        ("manual", "default"),
        ("auto mode", "auto"),
        ("plan mode", "plan"),
        ("auto", "auto"),
        ("plan", "plan"),
    ]
    let clean = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    for (needle, canonical) in modeMap {
        if clean == needle || clean.hasPrefix(needle + "\n") || clean.hasPrefix(needle + " ·") || clean.hasPrefix(needle + " (") {
            return canonical
        }
        if allowDescriptionSuffix && (clean.hasPrefix(needle + " ") || clean.hasPrefix(needle + "\t")) {
            return canonical
        }
    }
    return nil
}

func detectClaudeMode(_ nodes: [CollectedElem]) -> String {
    // 1. Primary in Claude Desktop 5.x: explicit "Permissions: <Mode>" button in the environment/toolbar row.
    for n in nodes where n.info.w > 4 && n.info.h > 4 {
        for lbl in elementLabels(n.info) {
            let lower = lbl.lowercased()
            if lower.hasPrefix("permissions:") {
                let rest = String(lbl.dropFirst("permissions:".count)).trimmingCharacters(in: .whitespacesAndNewlines)
                if let c = canonicalModeFromLabel(rest, allowDescriptionSuffix: false), c != "settingsDefault" {
                    return c
                }
            }
        }
    }
    // 2. Fallback: compact mode pill near the composer toolbar.
    let compY = findComposer(nodes)?.info.y ?? ((nodes.map { $0.info.y + $0.info.h }.max() ?? 1000.0) * 0.7)
    let toolbarNodes = nodes.filter {
        $0.info.w > 4 && $0.info.w < 240 && $0.info.h > 4 && $0.info.h < 50 && $0.info.y >= compY - 120
    }
    for n in toolbarNodes {
        for lbl in elementLabels(n.info) where lbl.count <= 28 {
            if let c = canonicalModeFromLabel(lbl, allowDescriptionSuffix: false), c != "settingsDefault" {
                return c
            }
        }
    }
    return "default"
}

var lastPopupDiag: String = ""

func elemSignature(_ e: ElemInfo) -> String {
    return "\(e.role):\(Int(e.x)),\(Int(e.y)):\(e.title)|\(e.desc)|\(e.value)"
}

func openPopupAndPick(
    appRef: AXUIElement,
    win: AXUIElement,
    trigger: CollectedElem,
    beforeNodes: [CollectedElem],
    matcher: ([CollectedElem]) -> CollectedElem?
) -> Bool {
    let beforeSigs = Set(beforeNodes.map { elemSignature($0.info) })

    func triggerOpen(useAXPress: Bool) -> ([CollectedElem], [CollectedElem]) {
        if useAXPress && trigger.info.actions.contains(kAXPressAction as String) {
            _ = AXUIElementPerformAction(trigger.ref, kAXPressAction as CFString)
        } else if trigger.info.w > 2 && trigger.info.h > 2 {
            clickPoint(trigger.info.x + trigger.info.w / 2.0, trigger.info.y + trigger.info.h / 2.0)
        } else {
            pressElement(trigger)
        }
        Thread.sleep(forTimeInterval: 0.45)
        let after = collectWindowNodes(appRef, primary: win)
        let fresh = after.filter { !beforeSigs.contains(elemSignature($0.info)) && $0.info.w > 4 && $0.info.h > 4 }
        return (after, fresh)
    }

    // Attempt 1: pointerdown click. If an earlier popup ate the first outside click, Attempt 2 opens it cleanly.
    var (afterNodes, freshNodes) = triggerOpen(useAXPress: false)
    if matcher(freshNodes) == nil {
        (afterNodes, freshNodes) = triggerOpen(useAXPress: false)
    }
    if matcher(freshNodes) == nil {
        (afterNodes, freshNodes) = triggerOpen(useAXPress: true)
    }

    let freshSummary = freshNodes
        .flatMap { elementLabels($0.info) }
        .map { String($0.replacingOccurrences(of: "\n", with: " ").prefix(45)) }
    lastPopupDiag = (Array(NSOrderedSet(array: freshSummary)) as? [String] ?? []).prefix(15).joined(separator: " | ")

    let nonTrigger = afterNodes.filter {
        !(abs($0.info.x - trigger.info.x) < 6 && abs($0.info.y - trigger.info.y) < 6)
    }
    if let opt = matcher(freshNodes) ?? matcher(nonTrigger) {
        if opt.info.w > 2 && opt.info.h > 2 {
            clickPoint(opt.info.x + opt.info.w / 2.0, opt.info.y + opt.info.h / 2.0)
        } else {
            pressElement(opt)
        }
        Thread.sleep(forTimeInterval: 0.35)
        let checkNodes = collectWindowNodes(appRef, primary: win)
        if let stillOpen = matcher(checkNodes.filter { !beforeSigs.contains(elemSignature($0.info)) }),
           abs(stillOpen.info.y - opt.info.y) < 16 {
            _ = AXUIElementPerformAction(stillOpen.ref, kAXPressAction as CFString)
            Thread.sleep(forTimeInterval: 0.25)
        }
        return true
    }

    sendKey(53) // Esc to close popup cleanly
    Thread.sleep(forTimeInterval: 0.25)
    return false
}

func findModelTrigger(_ nodes: [CollectedElem]) -> CollectedElem? {
    let actionableRoles: Set<String> = ["AXButton", "AXPopUpButton", "AXMenuButton"]
    if let explicit = nodes.first(where: { n in
        n.info.w > 8 && n.info.h > 8 &&
        (actionableRoles.contains(n.info.role) || n.info.actions.contains(kAXPressAction as String)) &&
        elementLabels(n.info).contains { $0.lowercased().hasPrefix("model:") }
    }) {
        return explicit
    }
    let compY = findComposer(nodes)?.info.y ?? ((nodes.map { $0.info.y + $0.info.h }.max() ?? 1000.0) * 0.7)
    return nodes.first(where: { n in
        n.info.w > 8 && n.info.w < 260 && n.info.h > 8 && n.info.h < 50 && n.info.y >= compY - 120 &&
        (actionableRoles.contains(n.info.role) || n.info.actions.contains(kAXPressAction as String)) &&
        elementLabels(n.info).contains { lbl in
            let l = lbl.lowercased()
            return !l.hasPrefix("usage:") && (l.contains("haiku") || l.contains("sonnet") || l.contains("opus"))
        }
    })
}

func selectClaudeModel(_ nodes: [CollectedElem], appRef: AXUIElement, win: AXUIElement, candidates: [String]) -> String? {
    guard let picker = findModelTrigger(nodes) else { return nil }
    let currentLabels = elementLabels(picker.info).joined(separator: " ").lowercased()
    for cand in candidates {
        if currentLabels.contains(cand.lowercased()) {
            return cand
        }
    }
    var picked: String? = nil
    let ok = openPopupAndPick(appRef: appRef, win: win, trigger: picker, beforeNodes: nodes) { pool in
        for cand in candidates {
            let needle = cand.lowercased()
            let hits = pool.filter { n in
                n.info.w > 8 && n.info.h > 8 &&
                elementLabels(n.info).contains { raw in
                    let l = raw.lowercased()
                    return !l.hasPrefix("model:") && !l.hasPrefix("usage:") && l.contains(needle)
                }
            }
            let actionable = hits.filter {
                $0.info.role == "AXMenuItem" || $0.info.role == "AXButton" || $0.info.role == "AXRadioButton" ||
                $0.info.actions.contains(kAXPressAction as String)
            }
            if let best = actionable.first ?? hits.first {
                picked = cand
                return best
            }
        }
        return nil
    }
    if ok, let p = picked {
        // Ensure the Model popup (which also houses Effort controls) is closed before the next step.
        sendKey(53)
        Thread.sleep(forTimeInterval: 0.20)
        return p
    }
    return nil
}

func selectClaudeLowEffort(_ appRef: AXUIElement, win: AXUIElement) {
    let nodes = collectWindowNodes(appRef, primary: win)
    guard let modelBtn = findModelTrigger(nodes) else { return }
    let modelLabel = elementLabels(modelBtn.info).joined(separator: " ").lowercased()
    if modelLabel.hasSuffix(" low") || modelLabel.contains(" low ") {
        return
    }

    let isLowLabel = { (raw: String) -> Bool in
        let l = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return l == "low" || l.hasPrefix("low ") || l.hasPrefix("low\n") || l.hasPrefix("low ·")
    }

    // 1. Check if there is a standalone Effort button ("High" / "Medium" / "Extra high" / "Max" / "Effort: ...") next to Model.
    let effortTriggers = nodes.filter { n in
        n.info.w > 8 && n.info.w < 200 && n.info.h > 8 && n.info.h < 50 &&
        abs(n.info.y - modelBtn.info.y) < 30 &&
        !(abs(n.info.x - modelBtn.info.x) < 6) &&
        elementLabels(n.info).contains { raw in
            let l = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return l == "high" || l == "medium" || l == "extra high" || l == "max" || l.hasPrefix("effort:")
        }
    }
    if let effBtn = effortTriggers.first {
        if openPopupAndPick(appRef: appRef, win: win, trigger: effBtn, beforeNodes: nodes, matcher: { pool in
            pool.first { n in n.info.w > 8 && n.info.h > 8 && elementLabels(n.info).contains(where: isLowLabel) }
        }) {
            sendKey(53)
            Thread.sleep(forTimeInterval: 0.20)
            return
        }
    }

    // 2. Otherwise open the "Model: ..." popup, which either embeds Effort inline or exposes an "Effort" submenu.
    let beforeSigs = Set(nodes.map { elemSignature($0.info) })
    clickPoint(modelBtn.info.x + modelBtn.info.w / 2.0, modelBtn.info.y + modelBtn.info.h / 2.0)
    Thread.sleep(forTimeInterval: 0.45)
    var fresh = collectWindowNodes(appRef, primary: win).filter {
        !beforeSigs.contains(elemSignature($0.info)) && $0.info.w > 6 && $0.info.h > 6
    }
    if fresh.isEmpty {
        clickPoint(modelBtn.info.x + modelBtn.info.w / 2.0, modelBtn.info.y + modelBtn.info.h / 2.0)
        Thread.sleep(forTimeInterval: 0.45)
        fresh = collectWindowNodes(appRef, primary: win).filter {
            !beforeSigs.contains(elemSignature($0.info)) && $0.info.w > 6 && $0.info.h > 6
        }
    }

    let pickLowIn = { (pool: [CollectedElem]) -> CollectedElem? in
        let hits = pool.filter { n in
            n.info.w > 8 && n.info.h > 8 && elementLabels(n.info).contains(where: isLowLabel)
        }
        let actionable = hits.filter {
            $0.info.role == "AXMenuItem" || $0.info.role == "AXButton" || $0.info.role == "AXRadioButton" ||
            $0.info.actions.contains(kAXPressAction as String)
        }
        return actionable.first ?? hits.first
    }

    if let directLow = pickLowIn(fresh) {
        pressElement(directLow)
        Thread.sleep(forTimeInterval: 0.30)
    } else if let effortSub = fresh.first(where: { n in
        n.info.w > 8 && n.info.h > 8 &&
        elementLabels(n.info).contains { raw in
            let l = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return l == "effort" || l.hasPrefix("effort ") || l.hasPrefix("effort\n") || l.hasPrefix("effort:")
        }
    }) {
        clickPoint(effortSub.info.x + effortSub.info.w / 2.0, effortSub.info.y + effortSub.info.h / 2.0)
        Thread.sleep(forTimeInterval: 0.45)
        let subFresh = collectWindowNodes(appRef, primary: win).filter {
            !beforeSigs.contains(elemSignature($0.info)) && $0.info.w > 6 && $0.info.h > 6
        }
        if let subLow = pickLowIn(subFresh) {
            if subLow.info.w > 2 && subLow.info.h > 2 {
                clickPoint(subLow.info.x + subLow.info.w / 2.0, subLow.info.y + subLow.info.h / 2.0)
            } else {
                pressElement(subLow)
            }
            Thread.sleep(forTimeInterval: 0.35)
        }
    }

    // Close the Model/Effort menu if still open so it never eats the next toolbar click.
    let postNodes = collectWindowNodes(appRef, primary: win)
    if postNodes.contains(where: { !beforeSigs.contains(elemSignature($0.info)) && $0.info.role == "AXMenuItem" && $0.info.w > 8 }) {
        sendKey(53)
        Thread.sleep(forTimeInterval: 0.25)
    }
}

func findPermissionsTrigger(_ nodes: [CollectedElem]) -> CollectedElem? {
    let actionableRoles: Set<String> = ["AXButton", "AXPopUpButton", "AXMenuButton"]
    if let explicit = nodes.first(where: { n in
        n.info.w > 8 && n.info.h > 8 &&
        (actionableRoles.contains(n.info.role) || n.info.actions.contains(kAXPressAction as String)) &&
        elementLabels(n.info).contains { $0.lowercased().hasPrefix("permissions:") }
    }) {
        return explicit
    }
    let compY = findComposer(nodes)?.info.y ?? ((nodes.map { $0.info.y + $0.info.h }.max() ?? 1000.0) * 0.7)
    return nodes.first(where: { n in
        n.info.w > 8 && n.info.w < 240 && n.info.h > 8 && n.info.h < 50 && n.info.y >= compY - 120 &&
        (actionableRoles.contains(n.info.role) || n.info.actions.contains(kAXPressAction as String)) &&
        elementLabels(n.info).contains { canonicalModeFromLabel($0) != nil }
    })
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
                return l == norm ||
                    l.hasPrefix(norm + "\n") ||
                    l.hasPrefix(norm + " ") ||
                    l.hasPrefix(norm + "⏎") ||
                    l.hasPrefix(norm + "esc") ||
                    l.hasPrefix("1. " + norm) ||
                    l.hasPrefix("2. " + norm) ||
                    l.hasPrefix("3. " + norm) ||
                    l.hasPrefix("4. " + norm)
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

func findSubmitButton(_ nodes: [CollectedElem]) -> CollectedElem? {
    let candidates = nodes.filter { n in
        guard n.info.w > 16 && n.info.h > 14 else { return false }
        guard n.info.role == "AXButton" || n.info.actions.contains(kAXPressAction as String) else { return false }
        return elementLabels(n.info).contains { raw in
            let l = raw.lowercased()
            return l == "submit" || l.hasPrefix("submit ") || l.hasPrefix("submit⌘") || l.hasPrefix("submit\n")
        }
    }
    return candidates.max(by: { $0.info.y < $1.info.y })
}

func findCardOption(_ nodes: [CollectedElem], target: String, submitY: Double) -> CollectedElem? {
    let inCard = nodes.filter { $0.info.y > submitY - 480 && $0.info.y < submitY + 14 }
    return findClickableText(inCard, target: target, exact: true)
}

func cardContainsMarker(_ nodes: [CollectedElem], submitY: Double, markerHint: String) -> Bool {
    guard !markerHint.isEmpty else { return true }
    return nodes.contains { n in
        guard n.info.w > 2 && n.info.h > 2 && n.info.y > submitY - 850 && n.info.y < submitY + 10 else { return false }
        return elementLabels(n.info).contains { raw in
            let l = raw.lowercased()
            return l.contains(markerHint) && !l.contains("use the shell tool")
        }
    }
}

func nodeIsCheckedOrSelected(_ e: ElemInfo) -> Bool {
    if e.selected { return true }
    if e.role == "AXRadioButton" || e.role == "AXCheckBox" {
        let v = e.value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return v == "1" || v == "true"
    }
    return false
}

func isCardOptionSelected(_ nodes: [CollectedElem], opt: CollectedElem, submitY: Double) -> (anySelectedInCard: Bool, targetSelected: Bool) {
    let cardNodes = nodes.filter { $0.info.y > submitY - 480 && $0.info.y < submitY - 20 && $0.info.w > 4 && $0.info.h > 4 }
    let anySel = cardNodes.contains { nodeIsCheckedOrSelected($0.info) }
    let optCenterY = opt.info.y + opt.info.h / 2.0
    let targetSel = cardNodes.contains {
        nodeIsCheckedOrSelected($0.info) && abs(($0.info.y + $0.info.h / 2.0) - optCenterY) < 18.0
    }
    return (anySel, targetSel)
}

func findRowRadioControl(_ nodes: [CollectedElem], opt: CollectedElem, submitY: Double) -> CollectedElem? {
    let optCenterY = opt.info.y + opt.info.h / 2.0
    return nodes.first { n in
        n.info.role == "AXRadioButton" &&
        n.info.w > 4 && n.info.h > 4 &&
        n.info.y > submitY - 480 && n.info.y < submitY - 20 &&
        abs((n.info.y + n.info.h / 2.0) - optCenterY) < 18.0
    }
}

func cardOptionIndex(_ nodes: [CollectedElem], target: String, submitY: Double) -> Int? {
    let knownOrder = ["Allow once", "Allow this session", "Explain", "Deny"]
    let present = knownOrder.filter { findCardOption(nodes, target: $0, submitY: submitY) != nil }
    return present.firstIndex(where: { $0.caseInsensitiveCompare(target) == .orderedSame })
}

func digitKeyCodeForCardOption(_ nodes: [CollectedElem], target: String, submitY: Double) -> CGKeyCode? {
    guard let idx = cardOptionIndex(nodes, target: target, submitY: submitY) else { return nil }
    // macOS Carbon keyCodes: '1'=18, '2'=19, '3'=20, '4'=21
    let codes: [CGKeyCode] = [18, 19, 20, 21]
    return idx < codes.count ? codes[idx] : nil
}

func cardRadioDiagSummary(_ nodes: [CollectedElem], submitY: Double) -> String {
    return nodes
        .filter { $0.info.y > submitY - 480 && $0.info.y < submitY + 14 && ($0.info.role == "AXRadioButton" || $0.info.selected || !elementLabels($0.info).isEmpty) }
        .prefix(25)
        .map { "\($0.info.role)[val=\($0.info.value),sel=\($0.info.selected),y=\(Int($0.info.y))]:\(elementLabels($0.info).first ?? "")" }
        .joined(separator: " | ")
}

func buttonDiagSummary(_ nodes: [CollectedElem]) -> String {
    let actionableRoles: Set<String> = ["AXButton", "AXRadioButton", "AXCheckBox", "AXMenuItem", "AXPopUpButton"]
    let labels = nodes
        .filter { $0.info.w > 2 && $0.info.h > 2 && actionableRoles.contains($0.info.role) }
        .flatMap { elementLabels($0.info) }
        .map { String($0.replacingOccurrences(of: "\n", with: " ").prefix(40)) }
    let unique = Array(NSOrderedSet(array: labels)) as? [String] ?? []
    let head = unique.prefix(12)
    let tail = unique.count > 12 ? unique.suffix(min(8, unique.count - 12)) : []
    return "kept=\(nodes.count) " + (Array(head) + Array(tail)).joined(separator: " | ")
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

case "dismiss-stale-trust":
    if let app = runningApp("Claude") {
        let appRef = AXUIElementCreateApplication(app.processIdentifier)
        enableAccessibility(appRef)
        if let win = targetWindow(appRef) {
            activateApp(app)
            var didDismiss = false
            for _ in 0..<4 {
                let nodes = collectWindowNodes(appRef, primary: win)
                let rawLabels = nodes.flatMap { elementLabels($0.info) }
                let allText = rawLabels.joined(separator: "\n").lowercased()
                let compactText = rawLabels.joined().lowercased()
                guard (allText.contains("yolonot-manual-") || compactText.contains("yolonot-manual-")) &&
                      allText.contains("trust this workspace") else {
                    break
                }
                didDismiss = true
                if let cancelBtn = findClickableText(nodes, target: "Cancel", exact: true) {
                    if cancelBtn.info.w > 2 && cancelBtn.info.h > 2 {
                        clickPoint(cancelBtn.info.x + cancelBtn.info.w / 2.0, cancelBtn.info.y + cancelBtn.info.h / 2.0)
                    } else {
                        pressElement(cancelBtn)
                    }
                    Thread.sleep(forTimeInterval: 0.35)
                    let afterCancel = collectWindowNodes(appRef, primary: win)
                    if let stillCancel = findClickableText(afterCancel, target: "Cancel", exact: true) {
                        _ = AXUIElementPerformAction(stillCancel.ref, kAXPressAction as CFString)
                        sendKey(53)
                        Thread.sleep(forTimeInterval: 0.35)
                    }
                } else {
                    sendKey(53)
                    Thread.sleep(forTimeInterval: 0.40)
                }
            }
            if didDismiss {
                print("dismissed")
                exit(0)
            }
        }
    }
    print("none")
    exit(0)

case "wait-ready":
    guard args.count >= 2 else { exit(2) }
    let appName = args[1]
    let timeout = args.count >= 3 ? (Double(args[2]) ?? 25.0) : 25.0
    let wsHint = args.count >= 4 ? args[3].lowercased() : ""
    let startTime = Date()
    let deadline = startTime.addingTimeInterval(timeout)
    let trustLabels = ["Trust workspace", "Trust folder", "Yes, I trust this folder"]
    var acceptedTrust = false
    while Date() < deadline {
        let (app, appRef, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectWindowNodes(appRef, primary: win)
        let rawLabels = nodes.flatMap { elementLabels($0.info) }
        let allText = rawLabels.joined(separator: "\n").lowercased()
        let compactText = rawLabels.joined().lowercased()
        let matchesHint = wsHint.isEmpty || allText.contains(wsHint) || compactText.contains(wsHint)

        // Handle Claude Desktop's "Trust this workspace?" dialog for our temporary sign-off folder.
        if let trustBtn = trustLabels.compactMap({ findClickableText(nodes, target: $0, exact: true) }).first {
            if matchesHint {
                Thread.sleep(forTimeInterval: 0.25)
                let settledNodes = collectWindowNodes(appRef, primary: win)
                let btn = trustLabels.compactMap({ findClickableText(settledNodes, target: $0, exact: true) }).first ?? trustBtn
                if btn.info.w > 2 && btn.info.h > 2 {
                    clickPoint(btn.info.x + btn.info.w / 2.0, btn.info.y + btn.info.h / 2.0)
                } else {
                    pressElement(btn)
                }
                Thread.sleep(forTimeInterval: 0.45)
                let checkTrust = collectWindowNodes(appRef, primary: win)
                if let stillTrust = trustLabels.compactMap({ findClickableText(checkTrust, target: $0, exact: true) }).first {
                    _ = AXUIElementPerformAction(stillTrust.ref, kAXPressAction as CFString)
                    if stillTrust.info.w > 2 && stillTrust.info.h > 2 {
                        clickPoint(stillTrust.info.x + stillTrust.info.w / 2.0, stillTrust.info.y + stillTrust.info.h / 2.0)
                    }
                }
                acceptedTrust = true
                Thread.sleep(forTimeInterval: 0.7)
                continue
            } else if allText.contains("yolonot-manual-") || compactText.contains("yolonot-manual-") {
                if let cancelBtn = findClickableText(nodes, target: "Cancel", exact: true) {
                    if cancelBtn.info.w > 2 && cancelBtn.info.h > 2 {
                        clickPoint(cancelBtn.info.x + cancelBtn.info.w / 2.0, cancelBtn.info.y + cancelBtn.info.h / 2.0)
                    } else {
                        pressElement(cancelBtn)
                    }
                } else {
                    sendKey(53)
                }
                Thread.sleep(forTimeInterval: 0.6)
                continue
            }
        }

        // Never report ready while the workspace trust modal is still covering the UI.
        if allText.contains("trust this workspace?") {
            Thread.sleep(forTimeInterval: 0.4)
            continue
        }

        if let comp = findComposer(nodes) {
            if matchesHint || acceptedTrust {
                print("ready:\(comp.info.role):\(Int(comp.info.x)),\(Int(comp.info.y))")
                exit(0)
            }
        }
        Thread.sleep(forTimeInterval: 0.4)
    }
    let (_, lastAppRef, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out waiting for composer input in \(appName). [ax-buttons: \(buttonDiagSummary(collectWindowNodes(lastAppRef, primary: lastWin)))]\n", stderr)
    exit(1)

case "claude-haiku":
    let (app, appRef, win) = requireWindow("Claude")
    activateApp(app)
    let nodes = collectWindowNodes(appRef, primary: win)
    let picked = selectClaudeModel(nodes, appRef: appRef, win: win, candidates: ["haiku"])
    selectClaudeLowEffort(appRef, win: win)
    let afterNodes = collectWindowNodes(appRef, primary: win)
    if let mBtn = findModelTrigger(afterNodes), let lbl = elementLabels(mBtn.info).first {
        print(lbl)
    } else if let p = picked {
        print("model:\(p)")
    } else {
        print("model:settings-local")
    }
    exit(0)

case "claude-mode":
    guard args.count >= 2 else { exit(2) }
    let want = args[1].lowercased() // "default" or "auto"
    let (app, appRef, win) = requireWindow("Claude")
    activateApp(app)
    for phase in 0..<2 {
        if phase == 1 && want == "auto" {
            // Claude Code disables Auto mode on Haiku; switch to Sonnet/Default if Auto wasn't listed.
            let nodes = collectWindowNodes(appRef, primary: win)
            _ = selectClaudeModel(nodes, appRef: appRef, win: win, candidates: ["sonnet", "default"])
            Thread.sleep(forTimeInterval: 0.4)
        }

        let startNodes = collectWindowNodes(appRef, primary: win)
        if detectClaudeMode(startNodes) == want {
            print("mode:\(want)")
            exit(0)
        }

        // 1. Click "Permissions: <Mode>" dropdown trigger directly and select "Manual" / "Auto".
        if let permTrigger = findPermissionsTrigger(startNodes) {
            _ = openPopupAndPick(appRef: appRef, win: win, trigger: permTrigger, beforeNodes: startNodes) { pool in
                let hits = pool.filter { n in
                    n.info.w > 8 && n.info.h > 8 &&
                    elementLabels(n.info).contains { raw in
                        !raw.lowercased().hasPrefix("permissions:") && canonicalModeFromLabel(raw) == want
                    }
                }
                let actionable = hits.filter {
                    $0.info.role == "AXMenuItem" || $0.info.role == "AXButton" || $0.info.role == "AXRadioButton" ||
                    $0.info.actions.contains(kAXPressAction as String)
                }
                return actionable.first ?? hits.first
            }
            Thread.sleep(forTimeInterval: 0.35)
            let postPopupNodes = collectWindowNodes(appRef, primary: win)
            if detectClaudeMode(postPopupNodes) == want {
                print("mode:\(want)")
                exit(0)
            }
        } else if let modelTrigger = findModelTrigger(startNodes) {
            // In active sessions with pickers in the title row, Permissions can live as a submenu inside Model.
            let beforeSigs = Set(startNodes.map { elemSignature($0.info) })
            clickPoint(modelTrigger.info.x + modelTrigger.info.w / 2.0, modelTrigger.info.y + modelTrigger.info.h / 2.0)
            Thread.sleep(forTimeInterval: 0.45)
            let menuNodes = collectWindowNodes(appRef, primary: win).filter { !beforeSigs.contains(elemSignature($0.info)) }
            if let permSub = findClickableText(menuNodes, target: "Permissions", exact: false) {
                clickPoint(permSub.info.x + permSub.info.w / 2.0, permSub.info.y + permSub.info.h / 2.0)
                Thread.sleep(forTimeInterval: 0.40)
                let subNodes = collectWindowNodes(appRef, primary: win).filter { !beforeSigs.contains(elemSignature($0.info)) }
                if let hit = subNodes.first(where: { n in
                    n.info.w > 8 && n.info.h > 8 &&
                    elementLabels(n.info).contains { !($0.lowercased().hasPrefix("permissions")) && canonicalModeFromLabel($0) == want }
                }) {
                    clickPoint(hit.info.x + hit.info.w / 2.0, hit.info.y + hit.info.h / 2.0)
                    Thread.sleep(forTimeInterval: 0.35)
                    print("mode:\(want)")
                    exit(0)
                }
            }
            sendKey(53)
            Thread.sleep(forTimeInterval: 0.25)
        }

        // 2. Fallback: focus composer and cycle modes via Shift+Tab.
        for attempt in 0..<6 {
            let nodes = collectWindowNodes(appRef, primary: win)
            if let comp = findComposer(nodes), attempt == 0 {
                clickPoint(comp.info.x + comp.info.w / 2.0, comp.info.y + comp.info.h / 2.0)
                Thread.sleep(forTimeInterval: 0.2)
            }
            let cur = detectClaudeMode(nodes)
            if cur == want {
                print("mode:\(cur)")
                exit(0)
            }
            sendKey(48, flags: .maskShift)
            Thread.sleep(forTimeInterval: 0.55)
        }
        if want != "auto" { break }
    }
    let finalNodes = collectWindowNodes(appRef, primary: win)
    let finalMode = detectClaudeMode(finalNodes)
    fputs("Failed to switch Claude mode to \(want) (stuck on \(finalMode)). [popup-fresh: \(lastPopupDiag)] [ax-buttons: \(buttonDiagSummary(finalNodes))]\n", stderr)
    exit(1)

case "send-prompt":
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let promptText = args[2]
    let (app, appRef, win) = requireWindow(appName)
    activateApp(app)
    // Wait up to ~12s if the previous assistant turn is still streaming ("Stop response" button visible).
    for _ in 0..<34 {
        let curNodes = collectWindowNodes(appRef, primary: win)
        if findClickableText(curNodes, target: "Stop response", exact: true) == nil {
            break
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    let nodes = collectWindowNodes(appRef, primary: win)
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

case "choose-ask":
    // Selects an option in Claude Desktop's AskUserQuestion radio card, verifies selection, and clicks Submit (⌘↵).
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let target = args[2]
    let timeout = args.count >= 4 ? (Double(args[3]) ?? 35.0) : 35.0
    let markerHint = args.count >= 5 ? args[4].lowercased() : ""
    let deadline = Date().addingTimeInterval(timeout)
    var prevSubmitY: Double? = nil
    var stableSince: Date? = nil
    var poll = 0
    while Date() < deadline {
        defer { poll += 1 }
        let (app, appRef, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectWindowNodes(appRef, primary: win)
        if let submitBtn = findSubmitButton(nodes),
           cardContainsMarker(nodes, submitY: submitBtn.info.y, markerHint: markerHint),
           findCardOption(nodes, target: target, submitY: submitBtn.info.y) != nil {
            // Claude Desktop enforces a 500ms bounding-rect settle guard (settledOnce: YY=500ms, XY=100ms)
            // during which clicks on approval options are ignored. Wait >= 0.70s of unchanged position.
            if let lastY = prevSubmitY, abs(submitBtn.info.y - lastY) < 2.0 {
                if stableSince == nil { stableSince = Date() }
            } else {
                prevSubmitY = submitBtn.info.y
                stableSince = Date()
            }
            if let since = stableSince, Date().timeIntervalSince(since) >= 0.70 {
                var verifiedOk = false
                for selectTry in 0..<5 {
                    let curNodes = collectWindowNodes(appRef, primary: win)
                    guard let curSub = findSubmitButton(curNodes),
                          let curOpt = findCardOption(curNodes, target: target, submitY: curSub.info.y) else { break }
                    let (preAnySel, preTargetSel) = isCardOptionSelected(curNodes, opt: curOpt, submitY: curSub.info.y)
                    if preTargetSel {
                        verifiedOk = true
                        break
                    }
                    let rowRadio = findRowRadioControl(curNodes, opt: curOpt, submitY: curSub.info.y)
                    switch selectTry {
                    case 0:
                        if curOpt.info.w > 2 && curOpt.info.h > 2 {
                            clickPoint(curOpt.info.x + curOpt.info.w / 2.0, curOpt.info.y + curOpt.info.h / 2.0)
                        } else {
                            pressElement(curOpt)
                        }
                    case 1:
                        if let r = rowRadio, r.info.w > 2 && r.info.h > 2 {
                            clickPoint(r.info.x + r.info.w / 2.0, r.info.y + r.info.h / 2.0)
                        } else {
                            _ = AXUIElementPerformAction(curOpt.ref, kAXPressAction as CFString)
                        }
                    case 2:
                        if let r = rowRadio {
                            _ = AXUIElementPerformAction(r.ref, kAXPressAction as CFString)
                        }
                        if curOpt.info.w > 2 && curOpt.info.h > 2 {
                            clickPoint(curOpt.info.x + min(curOpt.info.w * 0.25, 48.0), curOpt.info.y + curOpt.info.h / 2.0)
                        }
                    case 3:
                        if preAnySel, let digitKey = digitKeyCodeForCardOption(curNodes, target: target, submitY: curSub.info.y) {
                            if let r = rowRadio ?? Optional(curOpt), r.info.w > 2 && r.info.h > 2 {
                                clickPoint(r.info.x + r.info.w / 2.0, r.info.y + r.info.h / 2.0)
                                Thread.sleep(forTimeInterval: 0.12)
                            }
                            sendKey(digitKey)
                        }
                    default:
                        if let targetIdx = cardOptionIndex(curNodes, target: target, submitY: curSub.info.y), targetIdx > 0,
                           let firstOpt = findCardOption(curNodes, target: "Allow once", submitY: curSub.info.y) {
                            let anchor = findRowRadioControl(curNodes, opt: firstOpt, submitY: curSub.info.y) ?? firstOpt
                            clickPoint(anchor.info.x + anchor.info.w / 2.0, anchor.info.y + anchor.info.h / 2.0)
                            Thread.sleep(forTimeInterval: 0.15)
                            for _ in 0..<targetIdx {
                                sendKey(125) // ArrowDown
                                Thread.sleep(forTimeInterval: 0.10)
                            }
                            sendKey(49) // Space to check focused radio if needed
                        }
                    }
                    Thread.sleep(forTimeInterval: 0.25)
                    let check1 = collectWindowNodes(appRef, primary: win)
                    if let sub1 = findSubmitButton(check1),
                       let opt1 = findCardOption(check1, target: target, submitY: sub1.info.y) {
                        let (anySel, targetSel) = isCardOptionSelected(check1, opt: opt1, submitY: sub1.info.y)
                        if targetSel || !anySel {
                            verifiedOk = true
                            break
                        }
                    } else {
                        // Card already submitted immediately upon picking option ("submitted_by_pick").
                        print("submitted:\(target)")
                        exit(0)
                    }
                }

                let afterSelect = collectWindowNodes(appRef, primary: win)
                if !verifiedOk, let failSub = findSubmitButton(afterSelect) {
                    fputs("Failed to select radio option '\(target)' before Submit. [card-diag: \(cardRadioDiagSummary(afterSelect, submitY: failSub.info.y))]\n", stderr)
                    exit(1)
                }
                if let sub2 = findSubmitButton(afterSelect) {
                    if sub2.info.w > 2 && sub2.info.h > 2 {
                        clickPoint(sub2.info.x + sub2.info.w / 2.0, sub2.info.y + sub2.info.h / 2.0)
                    } else {
                        pressElement(sub2)
                    }
                    Thread.sleep(forTimeInterval: 0.45)

                    let afterSubmit = collectWindowNodes(appRef, primary: win)
                    if let sub3 = findSubmitButton(afterSubmit), abs(sub3.info.y - sub2.info.y) < 28 {
                        sendKey(36, flags: .maskCommand)
                        _ = AXUIElementPerformAction(sub3.ref, kAXPressAction as CFString)
                        Thread.sleep(forTimeInterval: 0.35)
                    }
                }
                print("submitted:\(target)")
                exit(0)
            }
            Thread.sleep(forTimeInterval: 0.25)
            continue
        }
        prevSubmitY = nil
        stableSince = nil
        // Fallback for older builds without a separate Submit button.
        if poll >= 3, findSubmitButton(nodes) == nil,
           let direct = findClickableText(nodes, target: target, exact: true),
           direct.info.role == "AXButton" {
            pressElement(direct)
            print("clicked:\(target)")
            exit(0)
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    let (_, lastAppRef, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out in choose-ask for '\(target)' in \(appName). [ax-buttons: \(buttonDiagSummary(collectWindowNodes(lastAppRef, primary: lastWin)))]\n", stderr)
    exit(1)

case "esc-ask":
    // Dismisses Claude Desktop's AskUserQuestion card unanswered (clicks "Skip" so $.ui.ask resolves
    // with no option rather than minimizing the banner, falling back to Escape on older builds).
    guard args.count >= 2 else { exit(2) }
    let appName = args[1]
    let timeout = args.count >= 3 ? (Double(args[2]) ?? 35.0) : 35.0
    let markerHint = args.count >= 4 ? args[3].lowercased() : ""
    let deadline = Date().addingTimeInterval(timeout)
    var prevSubmitY: Double? = nil
    var stableSince: Date? = nil
    while Date() < deadline {
        let (app, appRef, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectWindowNodes(appRef, primary: win)
        if let submitBtn = findSubmitButton(nodes),
           cardContainsMarker(nodes, submitY: submitBtn.info.y, markerHint: markerHint),
           let allowOpt = findCardOption(nodes, target: "Allow once", submitY: submitBtn.info.y) {
            if let lastY = prevSubmitY, abs(submitBtn.info.y - lastY) < 2.0 {
                if stableSince == nil { stableSince = Date() }
            } else {
                prevSubmitY = submitBtn.info.y
                stableSince = Date()
            }
            if let since = stableSince, Date().timeIntervalSince(since) >= 0.70 {
                if let skipBtn = findCardOption(nodes, target: "Skip", submitY: submitBtn.info.y + 20) ?? findClickableText(nodes, target: "Skip", exact: true) {
                    if skipBtn.info.w > 2 && skipBtn.info.h > 2 {
                        clickPoint(skipBtn.info.x + skipBtn.info.w / 2.0, skipBtn.info.y + skipBtn.info.h / 2.0)
                    } else {
                        pressElement(skipBtn)
                    }
                    Thread.sleep(forTimeInterval: 0.45)
                    let afterSkip = collectWindowNodes(appRef, primary: win)
                    if let stillSkip = findCardOption(afterSkip, target: "Skip", submitY: submitBtn.info.y + 20),
                       abs(stillSkip.info.y - skipBtn.info.y) < 24 {
                        _ = AXUIElementPerformAction(stillSkip.ref, kAXPressAction as CFString)
                        Thread.sleep(forTimeInterval: 0.35)
                    }
                    print("skipped")
                    exit(0)
                }
                if allowOpt.info.w > 2 && allowOpt.info.h > 2 {
                    clickPoint(allowOpt.info.x + allowOpt.info.w / 2.0, allowOpt.info.y + allowOpt.info.h / 2.0)
                    Thread.sleep(forTimeInterval: 0.20)
                }
                sendKey(53)
                Thread.sleep(forTimeInterval: 0.45)
                print("escaped")
                exit(0)
            }
            Thread.sleep(forTimeInterval: 0.25)
            continue
        }
        prevSubmitY = nil
        stableSince = nil
        Thread.sleep(forTimeInterval: 0.35)
    }
    let (_, lastAppRef, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out in esc-ask in \(appName). [ax-buttons: \(buttonDiagSummary(collectWindowNodes(lastAppRef, primary: lastWin)))]\n", stderr)
    exit(1)

case "wait-explained":
    // Waits until the follow-up AskUserQuestion card after "Explain" is open (has Allow once + Submit, no Explain option),
    // and prints all visible text lines in that card as JSON.
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let markerHint = args[2].lowercased()
    let timeout = args.count >= 4 ? (Double(args[3]) ?? 45.0) : 45.0
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let (app, appRef, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectWindowNodes(appRef, primary: win)
        if let submitBtn = findSubmitButton(nodes),
           let allowOpt = findCardOption(nodes, target: "Allow once", submitY: submitBtn.info.y),
           findCardOption(nodes, target: "Explain", submitY: submitBtn.info.y) == nil {
            let cardTexts = nodes
                .filter { $0.info.w > 1 && $0.info.h > 1 && $0.info.y >= allowOpt.info.y - 750 && $0.info.y <= submitBtn.info.y + 10 }
                .sorted { ($0.info.y, $0.info.x) < ($1.info.y, $1.info.x) }
                .flatMap { elementLabels($0.info) }
                .filter { !$0.lowercased().contains("use the shell tool") }
            if markerHint.isEmpty || cardTexts.contains(where: { $0.lowercased().contains(markerHint) }) {
                if let data = try? JSONEncoder().encode(cardTexts), let s = String(data: data, encoding: .utf8) {
                    print(s)
                }
                exit(0)
            }
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    let (_, lastAppRef, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out in wait-explained for '\(markerHint)' in \(appName). [ax-buttons: \(buttonDiagSummary(collectWindowNodes(lastAppRef, primary: lastWin)))]\n", stderr)
    exit(1)

case "click-text":
    guard args.count >= 3 else { exit(2) }
    let appName = args[1]
    let target = args[2]
    let timeout = args.count >= 4 ? (Double(args[3]) ?? 30.0) : 30.0
    let exact = !args.contains("--contains")
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        let (app, appRef, win) = requireWindow(appName, timeoutSec: 5.0)
        activateApp(app)
        let nodes = collectWindowNodes(appRef, primary: win)
        if let hit = findClickableText(nodes, target: target, exact: exact) {
            pressElement(hit)
            Thread.sleep(forTimeInterval: 0.45)
            // If synthetic AXPress did not dismiss the dialog button, fall back to a physical click.
            let afterNodes = collectWindowNodes(appRef, primary: win)
            if let stillThere = findClickableText(afterNodes, target: target, exact: exact),
               abs(stillThere.info.y - hit.info.y) < 16,
               stillThere.info.w > 2 && stillThere.info.h > 2 {
                clickPoint(stillThere.info.x + stillThere.info.w / 2.0, stillThere.info.y + stillThere.info.h / 2.0)
                Thread.sleep(forTimeInterval: 0.25)
            }
            print("clicked:\(hit.info.role):\(target)")
            exit(0)
        }
        Thread.sleep(forTimeInterval: 0.35)
    }
    let (_, lastAppRef, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out waiting to click '\(target)' in \(appName). [ax-buttons: \(buttonDiagSummary(collectWindowNodes(lastAppRef, primary: lastWin)))]\n", stderr)
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
    let (_, _, lastWin) = requireWindow(appName, timeoutSec: 3.0)
    fputs("Timed out in wait-text for '\(mustAppear)' in \(appName). [ax-buttons: \(buttonDiagSummary(collectTree(lastWin)))]\n", stderr)
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
