import AppKit
import SwiftUI
import UniformTypeIdentifiers

@MainActor
final class AppModel: ObservableObject {
  @Published var containers: [SavedContainer]
  @Published var states: [UUID: ContainerState] = [:]
  @Published var operation: OperationViewState?
  @Published var alert: String?
  @Published var statusError: String?
  @Published var refreshing = false
  weak var window: NSWindow?
  private var store: ContainerStore
  private let runBackend: BackendRunner
  private var persistenceError: String?
  private var channel: OperationChannel?
  private var refreshAgain = false
  private var afterRefresh: (() -> Void)?

  init(
    defaults: UserDefaults = .standard,
    runBackend: @escaping BackendRunner = { await RustBackend.run($0, channel: $1) }
  ) {
    store = ContainerStore(defaults: defaults)
    self.runBackend = runBackend
    containers = []
    do {
      containers = try store.load()
    } catch {
      persistenceError =
        "Saved containers could not be read. The saved records have been kept and will not be overwritten. You can still open containers manually."
      statusError = persistenceError
    }
  }

  var busy: Bool { operation != nil }
  var hasOpenContainers: Bool { states.values.contains(where: \.isOpen) }
  var needsQuitWarning: Bool {
    refreshing || persistenceError != nil || hasOpenContainers
      || containers.contains(where: { states[$0.id, default: .unknown] == .unknown })
  }

  func shouldQuit(confirm: () -> Bool) -> Bool {
    guard !busy else { return false }
    if needsQuitWarning && !confirm() { return false }
    // A modal confirmation can dispatch work that was queued by a status query.
    return !busy
  }

  func refresh() {
    guard beginRefresh() else { return }
    Task { await readStatus() }
  }

  func refreshStatus() async {
    guard beginRefresh() else { return }
    await readStatus()
  }

  private func beginRefresh() -> Bool {
    guard !busy, !refreshing else {
      refreshAgain = true
      return false
    }
    refreshing = true
    return true
  }

  private func readStatus() async {
    let result = await runBackend(["volumes"], OperationChannel { _ in })
    let volumes = result.code == 0 ? VolumeSnapshot(result.volumes) : nil
    let current = containers
    let files = await Task.detached {
      current.map { saved -> (SavedContainer, Bool) in
        var saved = saved
        let url = saved.resolve(volumes: volumes)
        return (saved, FileManager.default.fileExists(atPath: url.path))
      }
    }.value
    containers = files.map(\.0)
    saveContainers()
    states = Dictionary(
      uniqueKeysWithValues: files.map { saved, exists in
        (saved.id, ContainerState.resolve(path: saved.path, exists: exists, volumes: volumes))
      })
    let problems = [
      persistenceError,
      result.code == 0 ? nil : (result.error ?? "Could not read container status."),
    ].compactMap { $0 }
    statusError = problems.isEmpty ? nil : problems.joined(separator: "\n\n")
    refreshing = false
    if let action = afterRefresh {
      afterRefresh = nil
      action()
    }
    if refreshAgain && !busy {
      refreshAgain = false
      refresh()
    }
  }

  func openPicker() {
    guard !busy, let window, window.attachedSheet == nil else { return }
    let panel = NSOpenPanel()
    panel.title = "Open Container"
    panel.message = "Choose a container with its security-key file beside it."
    panel.prompt = "Open"
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.beginSheetModal(for: window) { [weak self] response in
      guard response == .OK, let url = panel.url else { return }
      Task { @MainActor in self?.addAndOpen(url) }
    }
  }

  func addAndOpen(_ url: URL) {
    guard !busy else {
      alert = "Finish the current operation before opening another container."
      return
    }
    if refreshing {
      deferUntilRefreshed { [weak self] in self?.addAndOpen(url) }
      return
    }
    let url = url.resolvingSymlinksInPath().standardizedFileURL
    guard !url.path.contains(where: { $0.isNewline || $0 == "\0" }) else {
      alert = "Choose a container whose path has no line breaks."
      return
    }
    guard FileManager.default.fileExists(atPath: url.path + ".fido2veracrypt_meta") else {
      alert =
        "The security-key file is missing. Keep the container and its .fido2veracrypt_meta file together."
      return
    }
    if let saved = containers.first(where: { $0.matches(url.path) }),
      case .open(let path) = states[saved.id]
    {
      showFiles(path)
      return
    }
    remember(url)
    perform(
      ["open", url.path], title: "Open \(url.deletingPathExtension().lastPathComponent)", url: url)
  }

  func createPicker() {
    guard !busy, let window, window.attachedSheet == nil else { return }
    let options = CreateOptions()
    let panel = NSSavePanel()
    panel.title = "Create Container"
    panel.prompt = "Create"
    panel.message = "Choose where to keep your encrypted files."
    panel.nameFieldStringValue = "Private.hc"
    panel.allowedContentTypes = [UTType(filenameExtension: "hc") ?? .data]
    panel.canCreateDirectories = true
    let accessory = NSHostingView(rootView: CreateOptionsView(options: options))
    accessory.frame = NSRect(x: 0, y: 0, width: 400, height: 112)
    panel.accessoryView = accessory
    let validation = NewContainerValidator(options: options)
    panel.delegate = validation
    panel.beginSheetModal(for: window) { [weak self, validation] response in
      _ = validation
      guard response == .OK, let url = panel.url else { return }
      Task { @MainActor in
        self?.perform(
          [
            "create", url.path, "--size", options.size + options.unit,
            "--label", options.label.trimmingCharacters(in: .whitespacesAndNewlines),
          ],
          title: "Create \(url.deletingPathExtension().lastPathComponent)", url: url)
      }
    }
  }

  private func remember(_ url: URL) {
    guard !containers.contains(where: { $0.matches(url.path) }) else { return }
    containers.append(SavedContainer(url: url))
    saveContainers()
  }

  private func saveContainers() {
    guard persistenceError == nil else { return }
    do {
      try store.save(containers)
    } catch {
      persistenceError =
        "The saved container list could not be updated. Its previous records were kept."
      statusError = persistenceError
    }
  }

  func forget(_ container: SavedContainer) {
    guard !busy, !refreshing, states[container.id, default: .unknown].canForget else { return }
    containers.removeAll { $0.id == container.id }
    states.removeValue(forKey: container.id)
    saveContainers()
  }

  func open(_ container: SavedContainer) {
    perform(["open", container.path], title: "Open \(container.name)", url: container.url)
  }
  func close(_ container: SavedContainer) {
    perform(["close", container.path], title: "Close \(container.name)", url: container.url)
  }
  func showFiles(_ path: String) { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }

  func cancel() {
    guard channel?.cancel() == true else { return }
    operation?.prompt = nil
    operation?.recovery = ""
    operation?.cancellable = false
    operation?.cancelled = true
    operation?.message = "Cancelling…"
    operation?.detail = "Wait for the key to finish responding."
  }

  func respond(_ answer: String) {
    operation?.prompt = nil
    operation?.recovery = ""
    channel?.respond(answer)
  }

  private func receive(_ message: BackendMessage, id: UUID) {
    guard operation?.id == id, operation?.cancelled == false else { return }
    switch message.kind {
    case .info, .warning:
      operation?.detail = message.text
    case .pin:
      operation?.prompt = .pin
      operation?.message = message.text
    case .confirm:
      operation?.prompt = .confirmation
      operation?.message = "Save your recovery phrase"
    case .recovery:
      operation?.recovery = message.text
    case .touch:
      operation?.prompt = nil
      operation?.message = message.text
      operation?.detail = message.detail
    case .working:
      operation?.prompt = nil
      operation?.recovery = ""
      operation?.cancellable = false
      operation?.message = message.text
      operation?.detail = "Keep the drive connected until this finishes."
    case .error, .volume, .check: break
    }
  }

  private func perform(_ arguments: [String], title: String, url: URL) {
    guard !busy else { return }
    if refreshing {
      deferUntilRefreshed { [weak self] in self?.perform(arguments, title: title, url: url) }
      return
    }
    guard !url.path.contains(where: { $0.isNewline || $0 == "\0" }) else {
      alert = "Choose a container whose path has no line breaks."
      return
    }
    let id = UUID()
    operation = OperationViewState(id: id, title: title)
    let channel = OperationChannel { [weak self] message in
      DispatchQueue.main.async { self?.receive(message, id: id) }
    }
    self.channel = channel
    Task {
      let result = await runBackend(arguments, channel)
      if FileManager.default.fileExists(atPath: url.path) { remember(url) }
      operation = nil
      self.channel = nil
      var notices = result.warnings
      if result.code == 1 {
        notices.insert(result.error ?? "The operation failed. Check the container's status.", at: 0)
      }
      if !notices.isEmpty { alert = notices.joined(separator: "\n\n") }
      // Failed Open can still leave a mount. Cancellation never establishes Closed.
      refresh()
    }
  }

  private func deferUntilRefreshed(_ action: @escaping () -> Void) {
    guard afterRefresh == nil else {
      alert =
        "A container operation is already waiting for the status check. Try again when it finishes."
      return
    }
    afterRefresh = action
  }
}

struct OperationViewState: Identifiable {
  enum Prompt: Equatable { case pin, confirmation }
  let id: UUID
  let title: String
  var message = "Checking the container…"
  var detail = ""
  var prompt: Prompt?
  var recovery = ""
  var cancellable = true
  var cancelled = false
}

@MainActor
final class CreateOptions: ObservableObject {
  @Published var size = "4"
  @Published var unit = "G"
  @Published var label = "My key"
}

@MainActor
final class NewContainerValidator: NSObject, NSOpenSavePanelDelegate {
  let options: CreateOptions
  init(options: CreateOptions) { self.options = options }
  func panel(_ sender: Any, validate url: URL) throws {
    let fm = FileManager.default
    let label = options.label.trimmingCharacters(in: .whitespacesAndNewlines)
    var problem: String?
    if fm.fileExists(atPath: url.path) || fm.fileExists(atPath: url.path + ".fido2veracrypt_meta") {
      problem = "That name is already used. Choose a new container name."
    } else if UInt64(options.size).map({ $0 > 0 }) != true {
      problem = "Enter a whole number greater than zero for the size."
    } else if label.isEmpty {
      problem = "Give this security key a name."
    } else if label.utf8.count > 256 {
      problem = "The security key name is too long. Use a shorter name."
    }
    if let problem {
      throw NSError(domain: "Fido2VC", code: 1, userInfo: [NSLocalizedDescriptionKey: problem])
    }
  }
}
