// poster <pid>: posts one key-down/key-up pair whose Unicode string is the
// launch marker, three times, with CGEvent.postToPid to <pid> ONLY. Refuses
// unless <pid> is a LaunchSpike binary under this spike's own directory.
// Never posts to the session, the HID tap or any other process.
import CoreGraphics
import Darwin
import Foundation

// "LNCHSPKMRK7QZX" XOR 0x5A (never stored in clear here).
let mx: [UInt8] = [0x16, 0x14, 0x19, 0x12, 0x09, 0x0a, 0x11, 0x17, 0x08, 0x11, 0x6d, 0x0b, 0x00, 0x02]

guard CommandLine.arguments.count == 2, let pid = pid_t(CommandLine.arguments[1]), pid > 1 else {
    print("usage: poster <pid>"); exit(2)
}
var buf = [CChar](repeating: 0, count: 4096)
guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { print("poster: no such pid"); exit(2) }
let path = String(cString: buf)
let root = "/scratchpad/p2/launch/build/"
let allowed = ["LaunchSpike", "LaunchSpikeNoEnv", "LaunchSpikeGTA"].contains { path.hasSuffix("/Contents/MacOS/" + $0) }
guard path.contains(root), allowed else {
    print("poster: refusing, pid \(pid) is \(path)"); exit(3)
}
var units = mx.map { UniChar($0 ^ 0x5A) }
for _ in 0..<3 {
    for down in [true, false] {
        guard let ev = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: down) else { print("poster: no event"); exit(4) }
        ev.keyboardSetUnicodeString(stringLength: units.count, unicodeString: &units)
        ev.postToPid(pid)
        usleep(60_000)
    }
    usleep(200_000)
}
print("poster: posted 3 key pairs to pid \(pid) (\(path))")
