// CGDisplayStream through dlsym from a binary built for macOS 26.0 (the API is obsoleted in the 15.0 SDK).
// Writes one frame, cropped to the rect given as x y w h (global points), to argv[1].
import AppKit
import CoreImage
import UniformTypeIdentifiers
typealias Create = @convention(c) (UInt32, Int, Int, Int32, CFDictionary?, DispatchQueue, @escaping @convention(block) (Int32, UInt64, IOSurfaceRef?, OpaquePointer?) -> Void) -> Unmanaged<AnyObject>?
typealias StartStop = @convention(c) (AnyObject) -> Int32
let h = dlopen(nil, RTLD_NOW)
guard let c = dlsym(h, "CGDisplayStreamCreateWithDispatchQueue"), let st = dlsym(h, "CGDisplayStreamStart"), let sp = dlsym(h, "CGDisplayStreamStop") else { print("symbols missing"); exit(1) }
print("deployment target of this binary: 26.0; symbols found via dlsym")
let a = CommandLine.arguments
let rect = CGRect(x: Double(a[2])!, y: Double(a[3])!, width: Double(a[4])!, height: Double(a[5])!)
let d = CGMainDisplayID()
var got: CGImage?
let sem = DispatchSemaphore(value: 0)
let blk: @convention(block) (Int32, UInt64, IOSurfaceRef?, OpaquePointer?) -> Void = { status, _, surf, _ in
    guard status == 0, got == nil, let surf = surf else { return }   // 0 = kCGDisplayStreamFrameStatusFrameComplete
    let ci = CIImage(ioSurface: surf)
    got = CIContext().createCGImage(ci, from: ci.extent); sem.signal()
}
guard let s = unsafeBitCast(c, to: Create.self)(d, CGDisplayPixelsWide(d) * 2, CGDisplayPixelsHigh(d) * 2, 0x42475241 /* BGRA */, nil, DispatchQueue(label: "q"), blk)?.takeRetainedValue() else { print("create NULL"); exit(1) }
print("start:", unsafeBitCast(st, to: StartStop.self)(s))
let r = sem.wait(timeout: .now() + 5)
print("stop:", unsafeBitCast(sp, to: StartStop.self)(s), "wait:", r == .success ? "frame" : "timeout")
guard let img = got else { exit(2) }
let crop = img.cropping(to: CGRect(x: rect.minX * 2, y: rect.minY * 2, width: rect.width * 2, height: rect.height * 2))!
let dst = CGImageDestinationCreateWithURL(URL(fileURLWithPath: a[1]) as CFURL, UTType.png.identifier as CFString, 1, nil)!
CGImageDestinationAddImage(dst, crop, nil); CGImageDestinationFinalize(dst)
print("saved crop \(crop.width)x\(crop.height) -> \(a[1])")
