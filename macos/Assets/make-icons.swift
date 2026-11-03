// Regenerate with: swift macos/Assets/make-icons.swift macos/Assets
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let fm = FileManager.default
try fm.createDirectory(at: output, withIntermediateDirectories: true)
let iconset = output.appendingPathComponent("AppIcon.iconset", isDirectory: true)
try fm.createDirectory(at: iconset, withIntermediateDirectories: true)

func color(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat) -> NSColor {
  NSColor(srgbRed: red / 255, green: green / 255, blue: blue / 255, alpha: 1)
}

func dockMark() {
  let tile = NSBezierPath(
    roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
  color(35, 41, 55).setFill()
  tile.fill()

  color(240, 180, 58).setFill()
  NSBezierPath(
    roundedRect: NSRect(x: 276, y: 246, width: 472, height: 400), xRadius: 36, yRadius: 36
  ).fill()
  NSBezierPath(
    roundedRect: NSRect(x: 240, y: 670, width: 544, height: 100), xRadius: 24, yRadius: 24
  ).fill()
  color(35, 41, 55).setFill()
  NSBezierPath(
    roundedRect: NSRect(x: 424, y: 510, width: 176, height: 42), xRadius: 13, yRadius: 13
  ).fill()
}

func menuMark() {
  NSColor.black.set()
  let body = NSBezierPath(
    roundedRect: NSRect(x: 4, y: 3, width: 14, height: 11.5), xRadius: 1.2, yRadius: 1.2)
  body.append(
    NSBezierPath(
      roundedRect: NSRect(x: 8, y: 10, width: 6, height: 1.7), xRadius: 0.6, yRadius: 0.6))
  body.windingRule = .evenOdd
  body.fill()
  NSBezierPath(
    roundedRect: NSRect(x: 2.7, y: 16, width: 16.6, height: 3), xRadius: 0.7, yRadius: 0.7
  ).fill()
}

func png(size: Int, canvas: CGFloat, drawing: () -> Void) throws -> Data {
  let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0, bitsPerPixel: 0)!
  NSGraphicsContext.saveGraphicsState()
  NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
  let transform = NSAffineTransform()
  transform.scale(by: CGFloat(size) / canvas)
  transform.concat()
  drawing()
  NSGraphicsContext.restoreGraphicsState()
  return bitmap.representation(using: .png, properties: [:])!
}

for size in [16, 32, 128, 256, 512] {
  try png(size: size, canvas: 1024, drawing: dockMark).write(
    to: iconset.appendingPathComponent("icon_\(size)x\(size).png"))
  try png(size: size * 2, canvas: 1024, drawing: dockMark).write(
    to: iconset.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
try png(size: 1024, canvas: 1024, drawing: dockMark).write(
  to: output.appendingPathComponent("AppIcon.png"))
try png(size: 88, canvas: 22, drawing: menuMark).write(
  to: output.appendingPathComponent("MenuBarPreview.png"))

let consumer = CGDataConsumer(url: output.appendingPathComponent("MenuBarIcon.pdf") as CFURL)!
var bounds = CGRect(x: 0, y: 0, width: 22, height: 22)
let context = CGContext(consumer: consumer, mediaBox: &bounds, nil)!
context.beginPDFPage(nil)
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
menuMark()
NSGraphicsContext.restoreGraphicsState()
context.endPDFPage()
context.closePDF()

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = [
  "-c", "icns", "-o", output.appendingPathComponent("AppIcon.icns").path, iconset.path,
]
try iconutil.run()
iconutil.waitUntilExit()
precondition(iconutil.terminationStatus == 0)
