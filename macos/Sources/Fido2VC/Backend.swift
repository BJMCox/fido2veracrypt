import Backend
import Foundation

enum BackendEvent: UInt32, Sendable {
  case info = 1
  case pin, confirm, recovery, touch, working, volume, error, check, warning
}

struct BackendMessage: Sendable {
  let kind: BackendEvent
  let text: String
  let detail: String
}

struct BackendResult: Sendable {
  let code: Int32
  let error: String?
  let warnings: [String]
  let volumes: [String: String]
}

typealias BackendRunner = @Sendable ([String], OperationChannel) async -> BackendResult

/// The condition owns cancellation and answers. Its lifetime extends through the C call,
/// including the time a cancelled HID operation takes to return.
final class OperationChannel: @unchecked Sendable {
  private let condition = NSCondition()
  private var cancelled = false
  private var cancellable = true
  private var waiting = false
  private var answer: Data?
  private var error: String?
  private var warnings: [String] = []
  private var volumes: [String: String] = [:]
  private let deliver: @Sendable (BackendMessage) -> Void

  init(deliver: @escaping @Sendable (BackendMessage) -> Void) { self.deliver = deliver }

  @discardableResult
  func cancel() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    guard cancellable else { return false }
    cancelled = true
    clearAnswer()
    condition.broadcast()
    return true
  }

  func respond(_ text: String) {
    condition.lock()
    defer { condition.unlock() }
    guard waiting, !cancelled else { return }
    answer = Data(text.utf8)
    waiting = false
    condition.signal()
  }

  private func clearAnswer() {
    if let count = answer?.count { answer?.resetBytes(in: 0..<count) }
    answer = nil
  }

  func receive(_ message: BackendMessage, response: UnsafeMutablePointer<UInt8>?, capacity: Int)
    -> Int
  {
    condition.lock()
    defer { condition.unlock() }
    guard !cancelled else { return -1 }
    if message.kind == .check { return 0 }
    if message.kind == .working { cancellable = false }
    if message.kind == .volume {
      // An attached file can move and its old path can be reused. Keep VeraCrypt's
      // identity; resolving that path now could name a different container.
      volumes[message.text] = message.detail
      return 0
    }
    if message.kind == .error { error = message.text }
    if message.kind == .warning { warnings.append(message.text) }
    let needsAnswer = message.kind == .pin || message.kind == .confirm
    if needsAnswer { waiting = true }
    deliver(message)
    guard needsAnswer else { return 0 }
    while waiting && !cancelled { condition.wait() }
    defer { clearAnswer() }
    guard !cancelled, let count = answer?.count, count <= capacity, let response else { return -1 }
    answer?.copyBytes(to: response, count: count)
    return count
  }

  func result(_ code: Int32) -> BackendResult {
    condition.lock()
    defer { condition.unlock() }
    return BackendResult(code: code, error: error, warnings: warnings, volumes: volumes)
  }
}

private let callback: FvcCallback = {
  context, kind, text, textLength, detail, detailLength, response, capacity in
  guard let context, let event = BackendEvent(rawValue: kind), let text, let detail else {
    return -1
  }
  // Copy the borrowed spans before dispatching a message to the main actor.
  let message = BackendMessage(
    kind: event,
    text: String(decoding: UnsafeBufferPointer(start: text, count: textLength), as: UTF8.self),
    detail: String(decoding: UnsafeBufferPointer(start: detail, count: detailLength), as: UTF8.self)
  )
  return Unmanaged<OperationChannel>.fromOpaque(context).takeUnretainedValue()
    .receive(message, response: response, capacity: capacity)
}

enum RustBackend {
  static func run(_ arguments: [String], channel: OperationChannel) async -> BackendResult {
    await Task.detached {
      // These arguments contain only commands, paths, sizes, and labels.
      let strings = arguments.map { strdup($0)! }
      defer {
        for string in strings { free(string) }
      }
      let pointers = strings.map { Optional(UnsafePointer($0)) }
      let code = pointers.withUnsafeBufferPointer { buffer in
        withExtendedLifetime(channel) {
          fvc_run(
            buffer.count, buffer.baseAddress, callback, Unmanaged.passUnretained(channel).toOpaque()
          )
        }
      }
      return channel.result(code)
    }.value
  }
}
