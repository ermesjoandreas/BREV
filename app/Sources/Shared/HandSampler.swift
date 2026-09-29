// HandSampler.swift — Hand's raw observations of this Mac.
//
// Upholds docs/AUTHORSHIP.md §2.2, §3.1 and §4.3 (docs/DECISIONS.md D-0109,
// D-0111): facts, not flags. The app reads what it can see and hands it to
// Rust as it is, and Rust counts: sudo and agents from the process names,
// other apps' windows from the window list, SIP from its bits. Nothing here
// counts, filters or judges, so the app has no way to say "0 agents"
// without hiding the names it read. The reads, all without a prompt in the
// sandbox (the Hand spike, D-0108):
// - secure event input: `IsSecureEventInputEnabled()`, the system's state;
// - SIP: `csr_get_active_config` (libSystem; not in Swift's Darwin module,
//   so through dlsym), nil unless it returns 0;
// - process names: `sysctl` KERN_PROC_ALL, each process's `p_comm` (at most
//   16 bytes), nil on failure (`proc_listallpids` is blocked in the sandbox);
// - windows: `CGWindowListCopyWindowInfo(.optionOnScreenOnly)`, of which
//   only each window's owner pid and layer are read; titles and owner names
//   are never read or kept (without Screen Recording there are no titles);
// - admin: `mbr_check_membership` of the user in group 80 (dlsym), once per
//   compose session, nil on failure.
// The window's own settings (sharingType, the protected layer) are added by
// EnvironmentProbe in the app, which has AppKit. Process names and window
// data exist only in the Sample of one call, which the caller hands to Rust
// at once and drops; nothing is logged. No AppKit: compiled into the app,
// the harness and the lock probe.

import Carbon.HIToolbox
import CoreGraphics
import Darwin
import Foundation

enum HandSampler {
    /// `RTLD_DEFAULT`: dlsym searches every image the process has loaded.
    private static let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
    /// The admin group's id on macOS.
    private static let adminGroup: UInt32 = 80

    /// A sample now, with the window settings the caller read:
    /// `sharingNone` (the window it samples has `sharingType` `.none`) and
    /// `preventsCapture` (the protected layer prevents capture).
    static func sample(sharingNone: Bool, preventsCapture: Bool) -> Sample {
        Sample(secureInput: IsSecureEventInputEnabled(), sharingNone: sharingNone, preventsCapture: preventsCapture,
               csrConfig: csrConfig(), processes: processNames(), windows: windows())
    }

    /// The SIP configuration bits (`csr_get_active_config`), or nil when
    /// the call cannot be found or does not return 0.
    static func csrConfig() -> UInt32? {
        typealias Get = @convention(c) (UnsafeMutablePointer<UInt32>) -> Int32
        guard let symbol = dlsym(rtldDefault, "csr_get_active_config") else { return nil }
        var config: UInt32 = 0
        return unsafeBitCast(symbol, to: Get.self)(&config) == 0 ? config : nil
    }

    /// The name of every process (`sysctl` KERN_PROC_ALL, `p_comm`), or nil
    /// when either call fails.
    static func processNames() -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0 else { return nil }
        // Room for processes started between the two calls.
        size += 64 * MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: size / MemoryLayout<kinfo_proc>.stride)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return nil }
        return procs.prefix(size / MemoryLayout<kinfo_proc>.stride).map { name(of: $0) }
    }

    /// A process's `p_comm`: its name, at most 16 bytes, up to the first 0.
    private static func name(of process: kinfo_proc) -> String {
        withUnsafeBytes(of: process.kp_proc.p_comm) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    /// Every on-screen window's owner pid and layer, or nil when the list
    /// cannot be read or a window lacks either. Only these two keys are
    /// read from each window's dictionary.
    static func windows() -> [Window]? {
        guard let list = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as NSArray?,
              let entries = list as? [NSDictionary]
        else { return nil }
        var out: [Window] = []
        out.reserveCapacity(entries.count)
        for entry in entries {
            guard let pid = entry[kCGWindowOwnerPID as String] as? NSNumber,
                  let layer = entry[kCGWindowLayer as String] as? NSNumber
            else { return nil }
            out.append(Window(ownerPid: pid.int32Value, layer: layer.int32Value))
        }
        return out
    }

    /// Whether the user is in the admin group (`mbr_check_membership`), or
    /// nil when a call cannot be found or fails.
    static func isAdmin() -> Bool? {
        typealias IDToUUID = @convention(c) (UInt32, UnsafeMutablePointer<UInt8>) -> Int32
        typealias Check = @convention(c) (UnsafePointer<UInt8>, UnsafePointer<UInt8>,
                                          UnsafeMutablePointer<Int32>) -> Int32
        guard let userUUID = dlsym(rtldDefault, "mbr_uid_to_uuid"),
              let groupUUID = dlsym(rtldDefault, "mbr_gid_to_uuid"),
              let check = dlsym(rtldDefault, "mbr_check_membership")
        else { return nil }
        var user = [UInt8](repeating: 0, count: 16), group = [UInt8](repeating: 0, count: 16)
        var member: Int32 = 0
        guard unsafeBitCast(userUUID, to: IDToUUID.self)(getuid(), &user) == 0,
              unsafeBitCast(groupUUID, to: IDToUUID.self)(adminGroup, &group) == 0,
              unsafeBitCast(check, to: Check.self)(user, group, &member) == 0
        else { return nil }
        return member != 0
    }
}
