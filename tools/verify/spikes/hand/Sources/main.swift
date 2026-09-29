// Hand spike: App Attest + environment facts from a sandboxed, team-signed,
// windowless app. Prints KEY=VALUE lines to stdout only (open --stdout).
// Never prints process names, window titles or owner names: counts only.
import AppKit          // NSWorkspace.runningApplications only
import CommonCrypto
import CoreGraphics
import Darwin
import DeviceCheck
import Foundation

setvbuf(stdout, nil, _IOLBF, 0)
func out(_ k: String, _ v: Any) { print("\(k)=\(v)") }
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func sha256(_ s: String) -> Data {
    let d = Data(s.utf8)
    var h = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    d.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(d.count), &h) }
    return Data(h)
}
func errText(_ e: Error?) -> String {
    guard let e = e as NSError? else { return "nil" }
    return "\(e.domain)#\(e.code) \(e.localizedDescription)"
}

// Container footprint (count + newest mtime, no names), before and after.
func containerFootprint() -> String {
    let home = URL(fileURLWithPath: NSHomeDirectory())
    var n = 0; var newest = 0.0
    if let en = FileManager.default.enumerator(at: home, includingPropertiesForKeys: [.contentModificationDateKey], options: []) {
        for case let u as URL in en {
            n += 1
            if let d = (try? u.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate {
                newest = max(newest, d.timeIntervalSince1970)
            }
        }
    }
    return "entries:\(n) newest_mtime:\(Int(newest))"
}

let mode = (Bundle.main.object(forInfoDictionaryKey: "HandSpikeAttest") as? Bool) == true ? "attest" : "noattest"
out("mode", mode)
out("pid", getpid())
out("sandboxed", ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil)
out("container.before", containerFootprint())

// ---------------------------------------------------------------- A. App Attest
let svc = DCAppAttestService.shared
out("A.isSupported", svc.isSupported)

if mode == "attest" && svc.isSupported {
    let sem = DispatchSemaphore(value: 0)
    let attestString = "brev-hand-spike attest 2026-09-29"
    let a1String = "brev-hand-spike assertion 1"
    let a2String = "brev-hand-spike assertion 2"
    let cdhAttest = sha256(attestString), cdh1 = sha256(a1String), cdh2 = sha256(a2String)
    out("A.clientDataHash.attest.string", attestString)
    out("A.clientDataHash.attest.hex", hex(cdhAttest))
    out("A.clientDataHash.assert1.string", a1String)
    out("A.clientDataHash.assert1.hex", hex(cdh1))
    out("A.clientDataHash.assert2.string", a2String)
    out("A.clientDataHash.assert2.hex", hex(cdh2))

    var keyId: String?
    svc.generateKey { k, e in keyId = k; out("A.generateKey.error", errText(e)); sem.signal() }
    sem.wait()
    if let keyId {
        out("A.keyId", keyId)
        let t0 = Date()
        var attestation: Data?
        svc.attestKey(keyId, clientDataHash: cdhAttest) { d, e in attestation = d; out("A.attestKey.error", errText(e)); sem.signal() }
        sem.wait()
        out("A.attestKey.ms", Int(Date().timeIntervalSince(t0) * 1000))
        if let attestation {
            out("A.attestation.bytes", attestation.count)
            out("A.attestation.b64", attestation.base64EncodedString())
            for (label, cdh) in [("assert1", cdh1), ("assert2", cdh2)] {
                var assertion: Data?
                svc.generateAssertion(keyId, clientDataHash: cdh) { d, e in assertion = d; out("A.\(label).error", errText(e)); sem.signal() }
                sem.wait()
                if let assertion {
                    out("A.\(label).bytes", assertion.count)
                    out("A.\(label).b64", assertion.base64EncodedString())
                }
            }
        }
    }
}

// ------------------------------------------------------------ B. is_admin
if let pw = getpwuid(getuid()) {
    out("B.admin.getpwuid", "ok")
    var n: Int32 = 256
    var groups = [Int32](repeating: 0, count: 256)
    let r = getgrouplist(pw.pointee.pw_name, Int32(bitPattern: pw.pointee.pw_gid), &groups, &n)
    out("B.admin.getgrouplist.rc", r)
    out("B.admin.getgrouplist.count", n)
    out("B.admin.getgrouplist.has80", groups.prefix(Int(n)).contains(80))
} else {
    out("B.admin.getpwuid", "nil errno=\(errno)")
}
if let gr = getgrnam("admin") { out("B.admin.getgrnam.gid", gr.pointee.gr_gid) } else { out("B.admin.getgrnam", "nil errno=\(errno)") }
do {
    var gs = [gid_t](repeating: 0, count: 64)
    let c = getgroups(64, &gs)
    out("B.admin.getgroups.count", c)
    out("B.admin.getgroups.has80", c > 0 && gs.prefix(Int(c)).contains(80))
}
do {
    // membership.h (libSystem) is not in Swift's Darwin module; public API, reached via dlsym.
    typealias IdToUUID = @convention(c) (UInt32, UnsafeMutablePointer<UInt8>) -> Int32
    typealias CheckMember = @convention(c) (UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafeMutablePointer<Int32>) -> Int32
    let h = UnsafeMutableRawPointer(bitPattern: -2)
    if let a = dlsym(h, "mbr_uid_to_uuid"), let b = dlsym(h, "mbr_gid_to_uuid"), let c = dlsym(h, "mbr_check_membership") {
        var uu = [UInt8](repeating: 0, count: 16), gu = [UInt8](repeating: 0, count: 16)
        let r1 = unsafeBitCast(a, to: IdToUUID.self)(getuid(), &uu)
        let r2 = unsafeBitCast(b, to: IdToUUID.self)(80, &gu)
        var member: Int32 = -1
        let r3 = (r1 == 0 && r2 == 0) ? unsafeBitCast(c, to: CheckMember.self)(uu, gu, &member) : -1
        out("B.admin.mbr_check_membership", "rc_uid:\(r1) rc_gid:\(r2) rc_check:\(r3) member:\(member)")
    } else { out("B.admin.mbr_check_membership", "dlsym nil") }
}

// ------------------------------------------------------------ B. os_integrity
let RTLD_DEFAULT_ = UnsafeMutableRawPointer(bitPattern: -2)
typealias CsrGetActive = @convention(c) (UnsafeMutablePointer<UInt32>) -> Int32
typealias CsrCheck = @convention(c) (UInt32) -> Int32
if let sym = dlsym(RTLD_DEFAULT_, "csr_get_active_config") {
    var cfg: UInt32 = 0xFFFF_FFFF
    errno = 0
    let rc = unsafeBitCast(sym, to: CsrGetActive.self)(&cfg)
    out("B.sip.csr_get_active_config", "rc:\(rc) errno:\(errno) config:0x\(String(cfg, radix: 16))")
} else { out("B.sip.csr_get_active_config", "dlsym nil") }
if let sym = dlsym(RTLD_DEFAULT_, "csr_check") {
    let f = unsafeBitCast(sym, to: CsrCheck.self)
    // 0x2 = CSR_ALLOW_UNRESTRICTED_FS, 0x1 = CSR_ALLOW_UNTRUSTED_KEXTS; rc 0 = allowed (SIP relaxed)
    errno = 0
    let r2 = f(0x2); let e2 = errno
    errno = 0
    let r1 = f(0x1); let e1 = errno
    out("B.sip.csr_check", "unrestricted_fs rc:\(r2) errno:\(e2) untrusted_kexts rc:\(r1) errno:\(e1)")
} else { out("B.sip.csr_check", "dlsym nil") }
do {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
    p.arguments = ["status"]
    let pipe = Pipe()
    p.standardOutput = pipe; p.standardError = pipe
    do {
        try p.run(); p.waitUntilExit()
        let s = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        out("B.sip.csrutil.exit", p.terminationStatus)
        out("B.sip.csrutil.output", s.replacingOccurrences(of: "\n", with: " | "))
    } catch { out("B.sip.csrutil.run", errText(error)) }
}

// ------------------------------------------------------------ B. processes
let me = getpid()
do {
    let n = proc_listallpids(nil, 0)
    var pids = [pid_t](repeating: 0, count: Int(max(n, 0)) + 64)
    let got = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
    out("B.proc.proc_listallpids", "rc:\(got) errno:\(errno)")
    var pathOK = 0, bsdOK = 0, euid0 = 0, sudoByName = 0, setuidRootMine = 0
    var buf = [CChar](repeating: 0, count: 4096)  // PROC_PIDPATHINFO_MAXSIZE; larger gives EOVERFLOW
    for pid in pids.prefix(Int(max(got, 0))) where pid > 0 {
        if proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 { pathOK += 1 }
        var bi = proc_bsdinfo()
        let sz = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, Int32(MemoryLayout<proc_bsdinfo>.size))
        if sz == Int32(MemoryLayout<proc_bsdinfo>.size) {
            bsdOK += 1
            if bi.pbi_uid == 0 { euid0 += 1 }
            if bi.pbi_uid == 0 && bi.pbi_ruid == getuid() { setuidRootMine += 1 }
            let comm = withUnsafeBytes(of: bi.pbi_comm) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
            if comm == "sudo" { sudoByName += 1 }
        }
    }
    out("B.proc.listallpids.count", got)
    out("B.proc.pidpath.readable", pathOK)
    out("B.proc.pidinfo_bsd.readable", bsdOK)
    out("B.proc.pidinfo.euid0", euid0)
    out("B.proc.pidinfo.euid0_ruid_me", setuidRootMine)
    out("B.proc.pidinfo.sudo", sudoByName)
}
do {
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
    var size = 0
    let r0 = sysctl(&mib, 4, nil, &size, nil, 0)
    size += 64 * MemoryLayout<kinfo_proc>.stride
    var procs = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride)
    let r1 = sysctl(&mib, 4, &procs, &size, nil, 0)
    let count = r1 == 0 ? size / MemoryLayout<kinfo_proc>.stride : 0
    var euid0 = 0, sudo = 0, setuidRootMine = 0
    for kp in procs.prefix(count) {
        let euid = kp.kp_eproc.e_ucred.cr_uid
        if euid == 0 { euid0 += 1 }
        if euid == 0 && kp.kp_eproc.e_pcred.p_ruid == getuid() { setuidRootMine += 1 }
        let comm = withUnsafeBytes(of: kp.kp_proc.p_comm) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
        if comm == "sudo" { sudo += 1 }
    }
    out("B.proc.sysctl_KERN_PROC_ALL", "rc0:\(r0) rc1:\(r1)")
    out("B.proc.sysctl.count", count)
    out("B.proc.sysctl.euid0", euid0)
    out("B.proc.sysctl.euid0_ruid_me", setuidRootMine)
    out("B.proc.sysctl.sudo", sudo)
    // proc_pidpath / proc_pidinfo on the pids sysctl returned (proc_listallpids may be blocked).
    var pathOK = 0, pathOKroot = 0, bsdOK = 0, bsdSudo = 0, others = 0
    var lastPathErrno: Int32 = 0, lastInfoErrno: Int32 = 0
    var buf = [CChar](repeating: 0, count: 4096)  // PROC_PIDPATHINFO_MAXSIZE; larger gives EOVERFLOW
    for kp in procs.prefix(count) {
        let pid = kp.kp_proc.p_pid
        if pid <= 0 || pid == me { continue }
        others += 1
        errno = 0
        if proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 {
            pathOK += 1
            if kp.kp_eproc.e_ucred.cr_uid == 0 { pathOKroot += 1 }
        } else { lastPathErrno = errno }
        var bi = proc_bsdinfo()
        errno = 0
        if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bi, Int32(MemoryLayout<proc_bsdinfo>.size)) == Int32(MemoryLayout<proc_bsdinfo>.size) {
            bsdOK += 1
            let comm = withUnsafeBytes(of: bi.pbi_comm) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
            if comm == "sudo" { bsdSudo += 1 }
        } else { lastInfoErrno = errno }
    }
    out("B.proc.sysctlpids.others", others)
    out("B.proc.sysctlpids.pidpath.readable", "\(pathOK) (euid0:\(pathOKroot)) last_errno:\(lastPathErrno)")
    out("B.proc.sysctlpids.pidinfo_bsd.readable", "\(bsdOK) sudo:\(bsdSudo) last_errno:\(lastInfoErrno)")
}
do {
    let apps = NSWorkspace.shared.runningApplications
    out("B.proc.NSWorkspace.runningApplications.count", apps.count)
    out("B.proc.NSWorkspace.others", apps.filter { $0.processIdentifier != me }.count)
    out("B.proc.NSWorkspace.withBundleURL", apps.filter { $0.bundleURL != nil }.count)
}

// ------------------------------------------------------------ B. windows
out("B.win.CGPreflightScreenCaptureAccess", CGPreflightScreenCaptureAccess())
if let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] {
    let others = list.filter { ($0[kCGWindowOwnerPID as String] as? Int32).map { $0 != me } ?? true }
    let ownerName = others.filter { !(($0[kCGWindowOwnerName as String] as? String) ?? "").isEmpty }.count
    let winName = others.filter { !(($0[kCGWindowName as String] as? String) ?? "").isEmpty }.count
    let layer0 = others.filter { ($0[kCGWindowLayer as String] as? Int) == 0 }.count
    let owners = Set(others.compactMap { $0[kCGWindowOwnerPID as String] as? Int32 }).count
    out("B.win.onscreen.total", list.count)
    out("B.win.onscreen.notMine", others.count)
    out("B.win.onscreen.notMine.layer0", layer0)
    out("B.win.onscreen.notMine.distinctOwnerPIDs", owners)
    out("B.win.onscreen.notMine.withOwnerName", ownerName)
    out("B.win.onscreen.notMine.withWindowName", winName)
} else {
    out("B.win.CGWindowListCopyWindowInfo", "nil")
}

out("container.after", containerFootprint())
out("done", true)
fflush(stdout)
exit(0)
