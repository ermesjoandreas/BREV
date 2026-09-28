// FFI spike harness. Command-line only: no AppKit, no windows, nothing on screen.
// Usage: harness <case> <n> <allocMode> [extra]
//   allocMode: 0 pass-through, 1 probe Rust frees, 3 probe + zero Rust frees
// Prints one line: marker hits before, while live, and after everything is
// dropped and wiped by the caller as a careful app would.
import Foundation
import CoreText
import CoreGraphics

// "BREV-SECRET-BODY" XOR 0x5A; the key is opaque to the optimiser so the
// plain marker never exists as a constant.
let MARKER_X: [UInt8] = [0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                         0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03]
let KEY: UInt8 = CommandLine.arguments.count >= 0 ? 0x5A : 0

func fillMarker(_ p: UnsafeMutableRawBufferPointer) {
    let k = KEY
    for i in 0..<p.count { p[i] = MARKER_X[i % 16] ^ k }
}
func makeData(_ n: Int) -> Data {
    var d = Data(count: n)
    d.withUnsafeMutableBytes { fillMarker($0) }
    return d
}
@inline(never) func wipeInPlace(_ d: inout Data) {
    d.withUnsafeMutableBytes { b in
        if let p = b.baseAddress { _ = memset_s(p, b.count, 0, b.count) }
    }
}
/// Wipes the storage `d` points at even when it is shared (bypasses CoW).
/// Only meaningful for heap-backed Data (> 14 bytes on 64-bit).
@inline(never) func wipeStorage(_ d: Data) {
    d.withUnsafeBytes { b in
        if let p = b.baseAddress { _ = memset_s(UnsafeMutableRawPointer(mutating: p), b.count, 0, b.count) }
    }
}

struct Hits: CustomStringConvertible {
    var u8: UInt64 = 0, u16: UInt64 = 0, glyph: UInt64 = 0
    var tags: [Int: UInt64] = [:]
    var description: String {
        let t = tags.sorted { $0.key < $1.key }.map { "\($0.key):\($0.value)" }.joined(separator: ",")
        return "u8=\(u8) u16=\(u16) glyph=\(glyph) tags={\(t)}"
    }
}
@inline(never) func scan() -> Hits {
    var r = brev_scan_result()
    brev_scan(&r)
    var h = Hits(u8: r.utf8_hits, u16: r.utf16_hits, glyph: r.glyph_hits)
    withUnsafeBytes(of: &r.by_tag) { raw in
        let a = raw.bindMemory(to: UInt64.self)
        for i in 0..<256 where a[i] > 0 { h.tags[i] = a[i] }
    }
    return h
}

let args = CommandLine.arguments
let cse = args[1]
let n = Int(args[2])!
let amode = UInt8(args[3])!
let extra = args.count > 4 ? Int(args[4])! : 0
var live = Hits()

final class Sink: SpikeSink, @unchecked Sendable {
    let n: Int
    var ret: Data? = nil
    init(_ n: Int) { self.n = n }
    func put(body: Data) {
        if extra == 1 {
            var b = body            // second reference: the wipe below copies first (CoW)
            wipeInPlace(&b)
        } else {
            wipeStorage(body)       // wipes the shared storage itself
        }
    }
    func get() -> Data {
        let d = makeData(n)
        ret = d
        return d
    }
}

@inline(never) func run() {
    switch cse {
    // ---------- UniFFI paths ----------
    case "owned_in":            // Data -> Rust Vec<u8> argument
        var d = makeData(n)
        _ = spikeOwnedIn(body: d)
        live = scan()
        wipeInPlace(&d)
    case "borrowed_in":         // Data -> Rust &[u8] argument (ForeignBytes)
        var d = makeData(n)
        _ = spikeBorrowedIn(body: d)
        live = scan()
        wipeInPlace(&d)
    case "owned_out":           // Rust Vec<u8> return -> Data
        var d = spikeOwnedOut(len: UInt32(n))
        live = scan()
        wipeInPlace(&d)
    case "string_out":          // Rust String return -> String (cannot be wiped)
        let s = spikeStringOut(len: UInt32(n))
        live = scan()
        _ = s.utf8.count
    case "method_out":          // Arc object method -> Data
        let s = SpikeSession(len: UInt32(n))
        var d = s.body()
        live = scan()
        wipeInPlace(&d)
        s.wipe()
    case "chunk_out":           // Arc object, fetched in chunks of `extra` bytes into one wiped buffer
        let s = SpikeSession(len: UInt32(n))
        let total = Int(s.bodyLen())
        let dst = UnsafeMutableRawBufferPointer.allocate(byteCount: total, alignment: 16)
        var off = 0
        while off < total {
            var c = s.bodyChunk(offset: UInt32(off), len: UInt32(extra))
            c.withUnsafeBytes { src in
                UnsafeMutableRawBufferPointer(rebasing: dst[off..<(off + src.count)]).copyMemory(from: src)
            }
            off += c.count
            wipeInPlace(&c)
        }
        s.wipe()
        live = scan()
        _ = memset_s(dst.baseAddress!, total, 0, total)
        dst.deallocate()
    case "method_unlock":       // &[u8] into an object method (DEK shape)
        let s = SpikeSession(len: 0)
        var dek = makeData(n)
        _ = s.unlock(dek: dek)
        wipeInPlace(&dek)
        live = scan()           // expected: only Rust's own copy
        s.wipe()
    case "callback":            // Rust -> Swift callback arg, Swift -> Rust callback return
        let sink = Sink(n)
        _ = spikeCallback(sink: sink, len: UInt32(n))
        live = scan()
        if var r = sink.ret { sink.ret = nil; wipeInPlace(&r) }

    // ---------- Swift only ----------
    case "array_wipe":          // [UInt8], uniquely referenced, wiped in place
        var a = [UInt8](repeating: 0, count: n)
        a.withUnsafeMutableBytes { fillMarker($0) }
        live = scan()
        a.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
    case "array_cow":           // a second reference exists when we wipe
        var a = [UInt8](repeating: 0, count: n)
        a.withUnsafeMutableBytes { fillMarker($0) }
        let b = a
        a.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        live = scan()           // b still holds it
        _ = b.count
    case "array_grow":          // appended byte by byte (growth), then wiped in place
        var a = [UInt8]()
        if extra == 1 { a.reserveCapacity(n) }
        for i in 0..<n { a.append(MARKER_X[i % 16] ^ KEY) }
        a.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        live = scan()
    case "data_wipe":           // Data built here, uniquely referenced, wiped in place
        var d = makeData(n)
        live = scan()
        wipeInPlace(&d)
    case "data_from_cf":        // immutable CFData (what Security returns) bridged to Data
        let tmp = UnsafeMutableRawBufferPointer.allocate(byteCount: n, alignment: 16)
        fillMarker(tmp)
        let cf = CFDataCreate(nil, tmp.baseAddress!.assumingMemoryBound(to: UInt8.self), n)!
        _ = memset_s(tmp.baseAddress!, n, 0, n); tmp.deallocate()
        var d = cf as Data
        let sameStorage = d.withUnsafeBytes { $0.baseAddress == UnsafeRawPointer(CFDataGetBytePtr(cf)) }
        if extra == 1 { wipeStorage(d) } else { wipeInPlace(&d) }
        let afterWipeSame = d.withUnsafeBytes { $0.baseAddress == UnsafeRawPointer(CFDataGetBytePtr(cf)) }
        var cfZero = true
        let p = CFDataGetBytePtr(cf)!
        for i in 0..<n where p[i] != 0 { cfZero = false }
        print("data_from_cf: Data shares CFData bytes before wipe=\(sameStorage) after=\(afterWipeSame); CFData bytes all zero after wipe=\(cfZero)")
        live = scan()           // does the CFData still hold it?
        _ = CFDataGetLength(cf)
    case "string_bridge":       // String from bytes, bridged to NSString / CFString
        var d = makeData(n)
        let s = String(decoding: d, as: UTF8.self)
        wipeInPlace(&d)
        let ns = s as NSString
        let cfs = s as CFString
        _ = ns.length; _ = CFStringGetLength(cfs); _ = ns.character(at: 0)
        live = scan()
    case "coretext":            // Core Text layout + draw into an offscreen bitmap
        // extra 0: CFString over our own UTF-16 buffer (no copy); 1: Swift String
        let font = CTFontCreateWithName("Helvetica" as CFString, 12, nil)
        // glyph needle for the 16 marker characters
        var chars = [UniChar](repeating: 0, count: 16)
        for i in 0..<16 { chars[i] = UniChar(MARKER_X[i] ^ KEY) }
        var glyphs = [CGGlyph](repeating: 0, count: 16)
        _ = CTFontGetGlyphsForCharacters(font, chars, &glyphs, 16)
        chars.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        let gx = glyphs.map { $0 ^ 0x5A5A }
        glyphs.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        gx.withUnsafeBufferPointer { brev_scan_set_glyphs($0.baseAddress, 16) }

        let u16 = UnsafeMutablePointer<UniChar>.allocate(capacity: n)
        for i in 0..<n { u16[i] = UniChar(MARKER_X[i % 16] ^ KEY) }
        autoreleasepool {
            let str: CFString
            if extra == 1 {
                str = String(utf16CodeUnits: u16, count: n) as CFString
            } else {
                str = CFStringCreateWithCharactersNoCopy(nil, u16, n, kCFAllocatorNull)
            }
            let attrs = [kCTFontAttributeName: font] as CFDictionary
            let astr = CFAttributedStringCreate(nil, str, attrs)!
            let fs = CTFramesetterCreateWithAttributedString(astr)
            let w = 1200, h = 1600
            let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                                space: CGColorSpaceCreateDeviceRGB(),
                                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
            let frame = CTFramesetterCreateFrame(fs, CFRange(location: 0, length: 0),
                                                 CGPath(rect: CGRect(x: 0, y: 0, width: w, height: h), transform: nil), nil)
            CTFrameDraw(frame, ctx)
            live = scan()
        }
        for i in 0..<n { u16[i] = 0 }
        _ = memset_s(u16, n * 2, 0, n * 2)
        u16.deallocate()
    case "coretext_lines":      // Core Text, one CTLine per `extra` characters
        let font = CTFontCreateWithName("Helvetica" as CFString, 12, nil)
        var chars = [UniChar](repeating: 0, count: 16)
        for i in 0..<16 { chars[i] = UniChar(MARKER_X[i] ^ KEY) }
        var glyphs = [CGGlyph](repeating: 0, count: 16)
        _ = CTFontGetGlyphsForCharacters(font, chars, &glyphs, 16)
        chars.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        let gx = glyphs.map { $0 ^ 0x5A5A }
        glyphs.withUnsafeMutableBytes { _ = memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        gx.withUnsafeBufferPointer { brev_scan_set_glyphs($0.baseAddress, 16) }
        let u16 = UnsafeMutablePointer<UniChar>.allocate(capacity: n)
        for i in 0..<n { u16[i] = UniChar(MARKER_X[i % 16] ^ KEY) }
        let ctx = CGContext(data: nil, width: 1200, height: 1600, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpaceCreateDeviceRGB(),
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        let attrs = [kCTFontAttributeName: font] as CFDictionary
        var off = 0, y = 1580.0
        while off < n {
            let len = min(extra, n - off)
            autoreleasepool {
                let str = CFStringCreateWithCharactersNoCopy(nil, u16 + off, len, kCFAllocatorNull)!
                let astr = CFAttributedStringCreate(nil, str, attrs)!
                let line = CTLineCreateWithAttributedString(astr)
                ctx.textPosition = CGPoint(x: 4, y: y)
                CTLineDraw(line, ctx)
            }
            off += len
            y -= 14; if y < 10 { y = 1580 }
        }
        live = scan()
        _ = memset_s(u16, n * 2, 0, n * 2)
        u16.deallocate()
        if args.count > 5 {         // flush: lay out and draw one line of filler text
            autoreleasepool {
                let filler = String(repeating: "x", count: Int(args[5])!) as CFString
                let line = CTLineCreateWithAttributedString(CFAttributedStringCreate(nil, filler, attrs)!)
                ctx.textPosition = CGPoint(x: 4, y: 4)
                CTLineDraw(line, ctx)
            }
        }
    default:
        fatalError("unknown case \(cse)")
    }
}

spikeAllocMode(mode: amode)
spikeAllocReset()
let before = scan()
autoreleasepool { run() }
let after = scan()
let c = spikeAllocCounters()
print("case=\(cse) n=\(n) mode=\(amode) extra=\(extra) | before[\(before)] | live[\(live)] | after[\(after)] | rustFreesWithMarker(<=1K,>1K)=(\(c[0]),\(c[1])) unwiped=(\(c[2]),\(c[3]))")
