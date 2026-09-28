// axdump — reads the accessibility tree of ONE process (the InputLab test app). Read-only except --press.
//   axdump <pid>                         every element: attributes + values, parameterized attributes (and
//                                         AXStringForRange / AXAttributedStringForRange on {0,64}), actions
//   axdump <pid> --hit x,y [x,y ...]     AXUIElementCopyElementAtPosition (global CG coordinates)
//   axdump <pid> --press <title> [...]   AXPress on buttons / menu items whose AXTitle matches (never on a menu bar item)
import ApplicationServices
import Foundation

setvbuf(stdout, nil, _IOLBF, 0)
let args = CommandLine.arguments
guard args.count >= 2, let pid = pid_t(args[1]) else { print("usage: axdump <pid> [--hit x,y ...] [--press title ...]"); exit(2) }
let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary
guard AXIsProcessTrustedWithOptions(opts) else { print("not AX-trusted; stopping (no prompt requested)"); exit(3) }

let app = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(app, 2)

func attr(_ e: AXUIElement, _ n: String) -> CFTypeRef? {
    var v: CFTypeRef?
    return AXUIElementCopyAttributeValue(e, n as CFString, &v) == .success ? v : nil
}
func str(_ e: AXUIElement, _ n: String) -> String? { attr(e, n) as? String }
func describe(_ v: CFTypeRef?) -> String {
    guard let v else { return "<none>" }
    let tid = CFGetTypeID(v)
    if tid == CFStringGetTypeID() { return "\"\(v as! String)\"" }
    if tid == CFNumberGetTypeID() || tid == CFBooleanGetTypeID() { return "\(v)" }
    if tid == AXUIElementGetTypeID() {
        let e = v as! AXUIElement
        return "<elem \(str(e, kAXRoleAttribute) ?? "?") \(str(e, kAXTitleAttribute).map { "\"\($0)\"" } ?? "")>"
    }
    if tid == AXValueGetTypeID() {
        let av = v as! AXValue
        switch AXValueGetType(av) {
        case .cgPoint: var p = CGPoint.zero; AXValueGetValue(av, .cgPoint, &p); return "pt(\(Int(p.x)),\(Int(p.y)))"
        case .cgSize: var s = CGSize.zero; AXValueGetValue(av, .cgSize, &s); return "size(\(Int(s.width)),\(Int(s.height)))"
        case .cfRange: var r = CFRange(); AXValueGetValue(av, .cfRange, &r); return "range(\(r.location),\(r.length))"
        case .cgRect: var r = CGRect.zero; AXValueGetValue(av, .cgRect, &r); return "rect(\(r))"
        default: return "axvalue"
        }
    }
    if tid == CFArrayGetTypeID() {
        let arr = v as! [CFTypeRef]
        return "[" + arr.prefix(8).map { describe($0) }.joined(separator: ", ") + (arr.count > 8 ? ", …(\(arr.count))" : "") + "]"
    }
    if tid == CFDictionaryGetTypeID() {
        let d = v as! [String: CFTypeRef]
        return "{" + d.keys.sorted().map { "\($0): \(describe(d[$0]))" }.joined(separator: ", ") + "}"
    }
    if tid == CFAttributedStringGetTypeID() { return "attr\"\(CFAttributedStringGetString((v as! CFAttributedString)) as String)\"" }
    return "<\(CFCopyTypeIDDescription(tid) as String? ?? "?")>"
}

var count = 0
func dump(_ e: AXUIElement, _ depth: Int, _ path: String) {
    count += 1
    if depth > 14 || count > 600 { return }
    let pad = String(repeating: "  ", count: depth)
    var names: CFArray?
    AXUIElementCopyAttributeNames(e, &names)
    let an = (names as? [String]) ?? []
    print("\(pad)● \(path)  role=\(str(e, kAXRoleAttribute) ?? "nil") subrole=\(str(e, kAXSubroleAttribute) ?? "nil")")
    for n in an where n != kAXChildrenAttribute && n != kAXParentAttribute && n != kAXTopLevelUIElementAttribute && n != kAXWindowAttribute {
        print("\(pad)    \(n) = \(describe(attr(e, n)))")
    }
    var pnames: CFArray?
    AXUIElementCopyParameterizedAttributeNames(e, &pnames)
    let pn = (pnames as? [String]) ?? []
    if !pn.isEmpty { print("\(pad)    [param] \(pn.joined(separator: " "))") }
    var range = CFRange(location: 0, length: 64)
    let rv = AXValueCreate(.cfRange, &range)!
    for p in [kAXStringForRangeParameterizedAttribute, kAXAttributedStringForRangeParameterizedAttribute] {
        var out: CFTypeRef?
        let err = AXUIElementCopyParameterizedAttributeValue(e, p as CFString, rv, &out)
        if err == .success || pn.contains(p) { print("\(pad)    [param] \(p)({0,64}) err=\(err.rawValue) -> \(describe(out))") }
    }
    var acts: CFArray?
    AXUIElementCopyActionNames(e, &acts)
    if let acts = acts as? [String], !acts.isEmpty { print("\(pad)    [actions] \(acts.joined(separator: " "))") }
    var kids: [AXUIElement] = []
    if let c = attr(e, kAXChildrenAttribute) as? [AXUIElement] { kids = c }
    if depth == 0 {
        if let mb = attr(e, kAXMenuBarAttribute) { kids.insert(mb as! AXUIElement, at: 0) }
    }
    // The system Apple menu (recent items etc.) is not InputLab content and is skipped.
    if str(e, kAXRoleAttribute) == kAXMenuBarItemRole && str(e, kAXTitleAttribute) == "Apple" { print("\(pad)    (Apple menu children skipped)"); return }
    for (i, k) in kids.enumerated() { dump(k, depth + 1, "\(path)/\(i)") }
}

func findAll(_ e: AXUIElement, _ title: String, _ depth: Int, _ out: inout [AXUIElement], _ underMenuBar: Bool) {
    if depth > 14 { return }
    let role = str(e, kAXRoleAttribute) ?? ""
    if str(e, kAXTitleAttribute) == title && (role == kAXButtonRole || role == kAXMenuItemRole) { out.append(e) }
    var kids: [AXUIElement] = (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? []
    if depth == 0, let mb = attr(e, kAXMenuBarAttribute) { kids.insert(mb as! AXUIElement, at: 0) }
    for k in kids { findAll(k, title, depth + 1, &out, underMenuBar) }
}

if let i = args.firstIndex(of: "--hit") {
    for s in args[(i + 1)...] {
        if s.hasPrefix("--") { break }
        let xy = s.split(separator: ",").compactMap { Float($0) }
        guard xy.count == 2 else { continue }
        var el: AXUIElement?
        let err = AXUIElementCopyElementAtPosition(app, xy[0], xy[1], &el)
        var chain: [String] = []
        var cur = el
        while let c = cur, chain.count < 10 {
            chain.append("\(str(c, kAXRoleAttribute) ?? "?")\(str(c, kAXTitleAttribute).map { "\"\($0)\"" } ?? "")\(attr(c, kAXValueAttribute).map { " value=" + describe($0) } ?? "")")
            cur = attr(c, kAXParentAttribute).map { $0 as! AXUIElement }
        }
        print("HIT \(s) err=\(err.rawValue) chain=\(chain.joined(separator: " < "))")
        if let e = el {
            var pn: CFArray?
            AXUIElementCopyParameterizedAttributeNames(e, &pn)
            print("    hit element params=\((pn as? [String]) ?? [])")
        }
    }
} else if let i = args.firstIndex(of: "--press") {
    for title in args[(i + 1)...] {
        var found: [AXUIElement] = []
        findAll(app, title, 0, &found, false)
        if found.isEmpty { print("PRESS \"\(title)\": not found") }
        for e in found {
            let err = AXUIElementPerformAction(e, kAXPressAction as CFString)
            print("PRESS \"\(title)\" role=\(str(e, kAXRoleAttribute) ?? "?") err=\(err.rawValue)")
            usleep(300_000)
        }
    }
} else if args.contains("--replace") {
    // Probe of the undocumented AXReplaceRangeWithText parameterized attribute (InputLab only).
    var targets: [(String, AXUIElement)] = [("app", app)]
    if let w = (attr(app, kAXWindowsAttribute) as? [AXUIElement])?.first {
        targets.append(("window", w))
        for k in (attr(w, kAXChildrenAttribute) as? [AXUIElement]) ?? [] where str(k, kAXRoleAttribute) == kAXTextFieldRole { targets.append(("textfield", k)) }
    }
    if let f = attr(app, kAXFocusedUIElementAttribute) { targets.append(("focused", f as! AXUIElement)) }
    var r = CFRange(location: 0, length: 0)
    let rv = AXValueCreate(.cfRange, &r)!
    let shapes: [(String, CFTypeRef)] = [("range", rv), ("array[range,text]", [rv, "ZZINJ" as CFString] as CFArray),
        ("dict{AXRange,AXText}", ["AXRange": rv, "AXText": "ZZINJ"] as CFDictionary),
        ("dict{AXRange,AXString}", ["AXRange": rv, "AXString": "ZZINJ"] as CFDictionary)]
    for (tn, t) in targets {
        for (sn, p) in shapes {
            var out: CFTypeRef?
            let err = AXUIElementCopyParameterizedAttributeValue(t, "AXReplaceRangeWithText" as CFString, p, &out)
            print("REPLACE target=\(tn) param=\(sn) err=\(err.rawValue) out=\(describe(out)) value-after=\(describe(attr(t, kAXValueAttribute)))")
        }
    }
} else if args.contains("--menus") {
    func walk(_ e: AXUIElement, _ d: Int) {
        let role = str(e, kAXRoleAttribute) ?? ""
        if role == kAXMenuItemRole || role == kAXMenuBarItemRole {
            let t = str(e, kAXTitleAttribute) ?? ""
            if !t.isEmpty { print(String(repeating: "  ", count: d) + "\(role) \"\(t)\" enabled=\(describe(attr(e, kAXEnabledAttribute))) cmd=\(describe(attr(e, kAXMenuItemCmdCharAttribute)))") }
        }
        if role == kAXMenuBarItemRole && str(e, kAXTitleAttribute) == "Apple" { return }
        for k in (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? [] { walk(k, d + 1) }
    }
    if let mb = attr(app, kAXMenuBarAttribute) { walk(mb as! AXUIElement, 0) }
    print("focused=\(describe(attr(app, kAXFocusedUIElementAttribute)))")
} else {
    dump(app, 0, "app")
    print("elements=\(count)")
}
