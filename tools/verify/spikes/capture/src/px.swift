import AppKit
let a = CommandLine.arguments
let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: a[1]) as CFURL, nil)!
let img = CGImageSourceCreateImageAtIndex(src, 0, nil)!
let w = img.width, h = img.height
var buf = [UInt8](repeating: 0, count: w * h * 4)
let ctx = CGContext(data: &buf, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
var i = 2
while i + 1 < a.count { let x = Int(a[i])!, y = Int(a[i + 1])!; let o = (y * w + x) * 4; print("(\(x),\(y)) rgba=\(buf[o]),\(buf[o+1]),\(buf[o+2]),\(buf[o+3])"); i += 2 }
