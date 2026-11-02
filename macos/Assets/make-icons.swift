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
    roundedRect: NSRect(x: 70, y: 70, width: 884, height: 884), xRadius: 200, yRadius: 200)
  NSGraphicsContext.saveGraphicsState()
  let shadow = NSShadow()
  shadow.shadowColor = NSColor.black.withAlphaComponent(0.22)
  shadow.shadowBlurRadius = 24
  shadow.shadowOffset = NSSize(width: 0, height: -12)
  shadow.set()
  color(20, 77, 62).setFill()
  tile.fill()
  NSGraphicsContext.restoreGraphicsState()
  NSGradient(starting: color(17, 72, 58), ending: color(64, 154, 117))!.draw(in: tile, angle: 65)

  let shackle = NSBezierPath()
  shackle.move(to: NSPoint(x: 366, y: 562))
  shackle.line(to: NSPoint(x: 366, y: 686))
  shackle.curve(
    to: NSPoint(x: 658, y: 686), controlPoint1: NSPoint(x: 366, y: 864),
    controlPoint2: NSPoint(x: 658, y: 864))
  shackle.line(to: NSPoint(x: 658, y: 562))
  shackle.lineWidth = 70
  shackle.lineCapStyle = .round
  color(234, 238, 219).setStroke()
  shackle.stroke()

  let body = NSBezierPath(
    roundedRect: NSRect(x: 276, y: 246, width: 472, height: 372), xRadius: 70, yRadius: 70)
  NSGraphicsContext.saveGraphicsState()
  let bodyShadow = NSShadow()
  bodyShadow.shadowColor = NSColor.black.withAlphaComponent(0.2)
  bodyShadow.shadowBlurRadius = 20
  bodyShadow.shadowOffset = NSSize(width: 0, height: -14)
  bodyShadow.set()
  color(242, 238, 216).setFill()
  body.fill()
  NSGraphicsContext.restoreGraphicsState()
  NSGradient(starting: color(226, 231, 209), ending: color(255, 251, 232))!.draw(
    in: body, angle: 90)

  color(26, 86, 68).setFill()
  NSBezierPath(ovalIn: NSRect(x: 469, y: 422, width: 86, height: 86)).fill()
  let keyhole = NSBezierPath()
  keyhole.move(to: NSPoint(x: 496, y: 445))
  keyhole.line(to: NSPoint(x: 486, y: 367))
  keyhole.curve(
    to: NSPoint(x: 538, y: 367), controlPoint1: NSPoint(x: 486, y: 354),
    controlPoint2: NSPoint(x: 538, y: 354))
  keyhole.line(to: NSPoint(x: 528, y: 445))
  keyhole.close()
  keyhole.fill()
  color(65, 125, 94).setFill()
  NSBezierPath(ovalIn: NSRect(x: 344, y: 295, width: 15, height: 15)).fill()
  let slot = NSBezierPath()
  slot.move(to: NSPoint(x: 385, y: 302))
  slot.line(to: NSPoint(x: 446, y: 302))
  slot.lineWidth = 7
  slot.lineCapStyle = .round
  color(93, 139, 107).setStroke()
  slot.stroke()
}

func menuMark() {
  NSColor.black.set()
  let shackle = NSBezierPath()
  shackle.move(to: NSPoint(x: 7.3, y: 12.2))
  shackle.line(to: NSPoint(x: 7.3, y: 16.1))
  shackle.curve(
    to: NSPoint(x: 14.7, y: 16.1), controlPoint1: NSPoint(x: 7.3, y: 20.8),
    controlPoint2: NSPoint(x: 14.7, y: 20.8))
  shackle.line(to: NSPoint(x: 14.7, y: 12.2))
  shackle.lineWidth = 1.65
  shackle.lineCapStyle = .round
  shackle.stroke()
  let body = NSBezierPath(
    roundedRect: NSRect(x: 3.8, y: 3, width: 14.4, height: 10.5), xRadius: 2.1, yRadius: 2.1)
  body.lineWidth = 1.55
  body.stroke()
  NSBezierPath(ovalIn: NSRect(x: 9.6, y: 7.8, width: 2.8, height: 2.8)).fill()
  NSBezierPath(
    roundedRect: NSRect(x: 10.25, y: 5.8, width: 1.5, height: 3), xRadius: 0.6, yRadius: 0.6
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
