// capture-probe-26 — one CGDisplayStream frame through dlsym, from a binary
// built for macOS 26.0 (docs/VERIFY.md V7). The API is obsoleted for
// deployment targets from 15.0, so a current app cannot call it by name, but
// the symbols are still there. capture-probe --legacy runs this and judges
// the result. From the capture spike's cgds26 (tools/verify/spikes/capture).
//
// usage: capture-probe-26 <out.png> <display id> <x> <y> <w> <h>
//   writes the frame, cut to the rect (global points, origin top left), to
//   <out.png>; the whole frame is never saved. Exit 0 with a frame.

import AppKit
import CoreImage
import UniformTypeIdentifiers

typealias Create = @convention(c) (UInt32, Int, Int, Int32, CFDictionary?, DispatchQueue,
                                   @escaping @convention(block) (Int32, UInt64, IOSurfaceRef?, OpaquePointer?) -> Void)
    -> Unmanaged<AnyObject>?
typealias StartStop = @convention(c) (AnyObject) -> Int32

let a = CommandLine.arguments
guard a.count == 7, let id = UInt32(a[2]), let x = Double(a[3]), let y = Double(a[4]), let w = Double(a[5]), let h = Double(a[6]) else {
    print("usage: capture-probe-26 <out.png> <display id> <x> <y> <w> <h>")
    exit(2)
}
let handle = dlopen(nil, RTLD_NOW)
guard let create = dlsym(handle, "CGDisplayStreamCreateWithDispatchQueue"), let start = dlsym(handle, "CGDisplayStreamStart"),
      let stop = dlsym(handle, "CGDisplayStreamStop") else {
    print("   capture-probe-26: CGDisplayStream symbols not found")
    exit(1)
}
print("   capture-probe-26: deployment target 26.0; CGDisplayStream symbols found through dlsym")
let bounds = CGDisplayBounds(id)
let mode = CGDisplayCopyDisplayMode(id)
let pw = mode?.pixelWidth ?? Int(bounds.width) * 2, ph = mode?.pixelHeight ?? Int(bounds.height) * 2
var got: CGImage?
let sem = DispatchSemaphore(value: 0)
let block: @convention(block) (Int32, UInt64, IOSurfaceRef?, OpaquePointer?) -> Void = { status, _, surface, _ in
    guard status == 0, got == nil, let surface else { return }   // 0: kCGDisplayStreamFrameStatusFrameComplete
    let ci = CIImage(ioSurface: surface)
    got = CIContext().createCGImage(ci, from: ci.extent)
    sem.signal()
}
// kCGDisplayStreamShowCursor = false, when the constant is there too.
let props: CFDictionary? = dlsym(handle, "kCGDisplayStreamShowCursor").map { p in
    [p.assumingMemoryBound(to: CFString.self).pointee: kCFBooleanFalse!] as CFDictionary
}
guard let stream = unsafeBitCast(create, to: Create.self)(id, pw, ph, 0x4247_5241 /* 'BGRA' */, props, DispatchQueue(label: "cgds"), block)?
    .takeRetainedValue() else {
    print("   capture-probe-26: create returned NULL")
    exit(1)
}
print("   capture-probe-26: start=\(unsafeBitCast(start, to: StartStop.self)(stream))")
let r = sem.wait(timeout: .now() + 5)
_ = unsafeBitCast(stop, to: StartStop.self)(stream)
guard r == .success, let img = got else {
    print("   capture-probe-26: no frame in 5 s")
    exit(1)
}
let s = CGFloat(img.width) / bounds.width
let cut = CGRect(x: (x - bounds.minX) * s, y: (y - bounds.minY) * s, width: w * s, height: h * s).integral
    .intersection(CGRect(x: 0, y: 0, width: img.width, height: img.height))
guard let crop = img.cropping(to: cut),
      let dst = CGImageDestinationCreateWithURL(URL(fileURLWithPath: a[1]) as CFURL, UTType.png.identifier as CFString, 1, nil) else {
    print("   capture-probe-26: cannot cut or write")
    exit(1)
}
CGImageDestinationAddImage(dst, crop, nil)
CGImageDestinationFinalize(dst)
exit(0)
