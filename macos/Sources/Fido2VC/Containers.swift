import Foundation

/// Only these macOS-owned aliases are stable when a container's own path is reused.
private func attachmentKey(_ path: String) -> String {
  for root in ["/var", "/tmp", "/etc"] {
    let privateRoot = "/private" + root
    if path == privateRoot || path.hasPrefix(privateRoot + "/") {
      return String(path.dropFirst("/private".count))
    }
  }
  return path
}

struct VolumeSnapshot: Sendable {
  enum Attachment: Sendable {
    case volume(path: String, mount: String)
    case ambiguous
  }

  private let attachments: [String: Attachment]

  init(_ volumes: [String: String]) {
    var attachments: [String: Attachment] = [:]
    for (path, mount) in volumes {
      let key = attachmentKey(path)
      attachments[key] = attachments[key] == nil ? .volume(path: path, mount: mount) : .ambiguous
    }
    self.attachments = attachments
  }

  func attachment(for path: String) -> Attachment? { attachments[attachmentKey(path)] }
}

struct SavedContainer: Codable, Identifiable, Equatable, Sendable {
  let id: UUID
  var path: String
  var bookmark: Data?

  init(url: URL) {
    let url = url.resolvingSymlinksInPath().standardizedFileURL
    id = UUID()
    path = url.path
    bookmark = try? url.bookmarkData(
      options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
  }

  mutating func resolve(volumes: VolumeSnapshot?) -> URL {
    // VeraCrypt retains the original source path when an open file moves. Keep that
    // path for status and Close until a successful snapshot confirms it is detached.
    guard let volumes else { return url }
    switch volumes.attachment(for: path) {
    case .volume(let path, _)?:
      self.path = path
      return url
    case .ambiguous?: return url
    case nil: break
    }
    guard let bookmark else { return URL(fileURLWithPath: path) }
    var stale = false
    guard
      let url = try? URL(
        resolvingBookmarkData: bookmark, options: [.withoutUI, .withoutMounting],
        relativeTo: nil, bookmarkDataIsStale: &stale)
    else { return URL(fileURLWithPath: path) }
    path = url.resolvingSymlinksInPath().standardizedFileURL.path
    if stale {
      self.bookmark = try? url.bookmarkData(
        options: .minimalBookmark, includingResourceValuesForKeys: nil, relativeTo: nil)
    }
    return self.url
  }

  var url: URL { URL(fileURLWithPath: path) }
  var name: String { url.deletingPathExtension().lastPathComponent }
  func matches(_ path: String) -> Bool { attachmentKey(self.path) == attachmentKey(path) }
}

enum ContainerState: Equatable {
  case unknown, unavailable, closed
  case open(String)
  case halfClosed

  static func resolve(path: String, exists: Bool, volumes: VolumeSnapshot?) -> Self {
    guard !path.contains(where: { $0.isNewline || $0 == "\0" }) else { return .unknown }
    // A still-attached volume remains unlocked even if its source drive disappears.
    guard let volumes else { return .unknown }
    switch volumes.attachment(for: path) {
    case .volume(_, let mount)?: return mount.isEmpty ? .halfClosed : .open(mount)
    case .ambiguous?: return .unknown
    case nil: break
    }
    guard exists else { return .unavailable }
    return .closed
  }

  var label: String {
    switch self {
    case .unknown: "Status unknown"
    case .unavailable: "Drive or file unavailable"
    case .closed: "Closed"
    case .open: "Open"
    case .halfClosed: "Still unlocked"
    }
  }

  var isOpen: Bool {
    switch self {
    case .open, .halfClosed: true
    default: false
    }
  }

  var canForget: Bool { self == .closed || self == .unavailable }
}

struct ContainerStore {
  let defaults: UserDefaults
  private let key = "containers"
  private var loaded = false

  private enum Failure: Error { case invalidData, duplicateIdentity, notLoaded }

  init(defaults: UserDefaults) { self.defaults = defaults }

  mutating func load() throws -> [SavedContainer] {
    loaded = false
    guard let stored = defaults.object(forKey: key) else {
      loaded = true
      return []
    }
    guard let data = stored as? Data else { throw Failure.invalidData }
    let containers = try JSONDecoder().decode([SavedContainer].self, from: data)
    guard Set(containers.map(\.id)).count == containers.count else {
      throw Failure.duplicateIdentity
    }
    loaded = true
    return containers
  }

  func save(_ containers: [SavedContainer]) throws {
    guard loaded else { throw Failure.notLoaded }
    defaults.set(try JSONEncoder().encode(containers), forKey: key)
  }
}
