// No prompts: every check below is a preflight/query only.
import ApplicationServices
import CoreGraphics
import Foundation
let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary
print("AXIsProcessTrustedWithOptions(prompt:false) =", AXIsProcessTrustedWithOptions(opts))
print("CGPreflightPostEventAccess =", CGPreflightPostEventAccess())
print("CGPreflightListenEventAccess =", CGPreflightListenEventAccess())
print("CGPreflightScreenCaptureAccess =", CGPreflightScreenCaptureAccess())
print("pid =", getpid(), "ppid =", getppid())
