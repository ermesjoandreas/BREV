// axdump — docs/VERIFY.md V11 and V13: what the Accessibility API exposes of
// an app, and whether an AX press does anything.
//
// A verification tool, never linked into Brev.app. From the input spike's
// axdump (tools/verify/spikes/input). It needs the Accessibility permission
// for its responsible app (Terminal) and never asks for it.
//
// usage: axdump [<app name> | --pid <n>]                (default Brev)
//          every element (windows, sheets, the menu bar): all attributes with
//          their values, all parameterized attributes, and the read-only ones
//          called: those taking a range with {0,64}, those taking an index or
//          a line with 0, those taking a position with the element's
//          origin. AXReplaceRangeWithText and other writers are never called
//        axdump [<app> | --pid <n>] --press <title>...
//          AXPress on every button, checkbox or menu item with that title
//          and prints the AXError; the effect has to be judged from the app
//          (an app that refuses a press can still get 0 back, input spike)
//        axdump [<app> | --pid <n>] --hit <x,y>...      the element at a point
//        axdump [<app> | --pid <n>] --menus             the menu items only
// Exit 3 when not trusted for Accessibility or no such app.

import ApplicationServices
import AppKit

setvbuf(stdout, nil, _IOLBF, 0)
let args = Array(CommandLine.arguments.dropFirst())
let options: Set<String> = ["--press", "--hit", "--menus"]
let pid: pid_t
if let i = args.firstIndex(of: "--pid"), args.indices.contains(i + 1), let p = pid_t(args[i + 1]) {
    pid = p
} else {
    let name = args.first.flatMap { options.contains($0) ? nil : $0 } ?? "Brev"
    let running = NSWorkspace.shared.runningApplications.filter { $0.localizedName == name }
    guard running.count == 1, let only = running.first else {
        print("\(running.count) running apps named \(name); use --pid")
        exit(3)
    }
    pid = only.processIdentifier
}
guard AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary) else {
    print("not trusted for Accessibility: stopping (nothing requested)")
    exit(3)
}
let app = AXUIElementCreateApplication(pid)
AXUIElementSetMessagingTimeout(app, 2)
print("axdump pid \(pid)")

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
    if tid == CFDataGetTypeID() { return "data(\(CFDataGetLength((v as! CFData))) bytes) \"\(String(decoding: v as! Data, as: UTF8.self))\"" }
    return "<\(CFCopyTypeIDDescription(tid) as String? ?? "?")>"
}

/// The parameter a read-only parameterized attribute takes, by its name; nil
/// for anything else (writers such as AXReplaceRangeWithText, unknown shapes).
func parameter(_ name: String, _ e: AXUIElement) -> CFTypeRef? {
    if name.hasPrefix("AXReplace") || name.hasPrefix("AXSet") { return nil }
    if name.hasSuffix("ForRange") {
        var r = CFRange(location: 0, length: 64)
        return AXValueCreate(.cfRange, &r)
    }
    if name.hasSuffix("ForIndex") || name.hasSuffix("ForLine") { return 0 as CFNumber }
    if name.hasSuffix("ForPosition") {
        var p = attr(e, kAXPositionAttribute).map { v -> CGPoint in var pt = CGPoint.zero; AXValueGetValue(v as! AXValue, .cgPoint, &pt); return pt } ?? .zero
        return AXValueCreate(.cgPoint, &p)
    }
    return nil
}

var count = 0
func dump(_ e: AXUIElement, _ depth: Int, _ path: String) {
    count += 1
    if depth > 16 || count > 2000 { return }
    let pad = String(repeating: "  ", count: depth)
    var names: CFArray?
    AXUIElementCopyAttributeNames(e, &names)
    print("\(pad)● \(path)  role=\(str(e, kAXRoleAttribute) ?? "nil") subrole=\(str(e, kAXSubroleAttribute) ?? "nil")")
    for n in (names as? [String]) ?? [] where ![kAXChildrenAttribute, kAXParentAttribute, kAXTopLevelUIElementAttribute, kAXWindowAttribute].contains(n) {
        print("\(pad)    \(n) = \(describe(attr(e, n)))")
    }
    var pnames: CFArray?
    AXUIElementCopyParameterizedAttributeNames(e, &pnames)
    let pn = (pnames as? [String]) ?? []
    if !pn.isEmpty { print("\(pad)    [param] \(pn.joined(separator: " "))") }
    for p in Set(pn + [kAXStringForRangeParameterizedAttribute, kAXAttributedStringForRangeParameterizedAttribute]).sorted() {
        guard let arg = parameter(p, e) else { continue }
        var out: CFTypeRef?
        let err = AXUIElementCopyParameterizedAttributeValue(e, p as CFString, arg, &out)
        if err == .success || pn.contains(p) { print("\(pad)    [param] \(p)(\(describe(arg))) err=\(err.rawValue) -> \(describe(out))") }
    }
    var acts: CFArray?
    AXUIElementCopyActionNames(e, &acts)
    if let acts = acts as? [String], !acts.isEmpty { print("\(pad)    [actions] \(acts.joined(separator: " "))") }
    // The Apple menu is the system's, not the app's.
    if str(e, kAXRoleAttribute) == kAXMenuBarItemRole && str(e, kAXTitleAttribute) == "Apple" { print("\(pad)    (Apple menu skipped)"); return }
    var kids = (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? []
    if depth == 0, let mb = attr(e, kAXMenuBarAttribute) { kids.insert(mb as! AXUIElement, at: 0) }
    for (i, k) in kids.enumerated() { dump(k, depth + 1, "\(path)/\(i)") }
}

func find(_ e: AXUIElement, _ title: String, _ depth: Int, _ out: inout [AXUIElement]) {
    if depth > 16 { return }
    let role = str(e, kAXRoleAttribute) ?? ""
    if str(e, kAXTitleAttribute) == title && [kAXButtonRole, kAXMenuItemRole, kAXCheckBoxRole, kAXRadioButtonRole].contains(role) { out.append(e) }
    if role == kAXMenuBarItemRole && str(e, kAXTitleAttribute) == "Apple" { return }
    var kids = (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? []
    if depth == 0, let mb = attr(e, kAXMenuBarAttribute) { kids.insert(mb as! AXUIElement, at: 0) }
    for k in kids { find(k, title, depth + 1, &out) }
}

func following(_ flag: String) -> [String] {
    guard let i = args.firstIndex(of: flag) else { return [] }
    return Array(args[(i + 1)...].prefix { !$0.hasPrefix("--") })
}

if args.contains("--press") {
    for title in following("--press") {
        var found: [AXUIElement] = []
        find(app, title, 0, &found)
        if found.isEmpty { print("PRESS \"\(title)\": not found") }
        for e in found {
            let err = AXUIElementPerformAction(e, kAXPressAction as CFString)
            print("PRESS \"\(title)\" role=\(str(e, kAXRoleAttribute) ?? "?") AXError=\(err.rawValue)")
            usleep(300_000)
        }
    }
} else if args.contains("--hit") {
    for s in following("--hit") {
        let xy = s.split(separator: ",").compactMap { Float($0) }
        guard xy.count == 2 else { continue }
        var el: AXUIElement?
        let err = AXUIElementCopyElementAtPosition(app, xy[0], xy[1], &el)
        var chain: [String] = []
        var cur = el
        while let c = cur, chain.count < 12 {
            chain.append("\(str(c, kAXRoleAttribute) ?? "?")\(str(c, kAXTitleAttribute).map { "\"\($0)\"" } ?? "")\(attr(c, kAXValueAttribute).map { " value=" + describe($0) } ?? "")")
            cur = attr(c, kAXParentAttribute).map { $0 as! AXUIElement }
        }
        print("HIT \(s) AXError=\(err.rawValue) chain=\(chain.joined(separator: " < "))")
    }
} else if args.contains("--menus") {
    func walk(_ e: AXUIElement, _ d: Int) {
        let role = str(e, kAXRoleAttribute) ?? ""
        if role == kAXMenuItemRole || role == kAXMenuBarItemRole, let t = str(e, kAXTitleAttribute), !t.isEmpty {
            print(String(repeating: "  ", count: d) + "\(role) \"\(t)\" enabled=\(describe(attr(e, kAXEnabledAttribute))) cmd=\(describe(attr(e, kAXMenuItemCmdCharAttribute)))")
        }
        if role == kAXMenuBarItemRole && str(e, kAXTitleAttribute) == "Apple" { return }
        for k in (attr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? [] { walk(k, d + 1) }
    }
    if let mb = attr(app, kAXMenuBarAttribute) { walk(mb as! AXUIElement, 0) }
} else {
    dump(app, 0, "app")
    print("elements=\(count)")
}
