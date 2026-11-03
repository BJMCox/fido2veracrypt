import Darwin
import Foundation
import Testing

@testable import Fido2VC

@Test func failedSnapshotDoesNotMeanClosed() {
  #expect(
    ContainerState.resolve(path: "/unsupported\n.hc", exists: true, volumes: VolumeSnapshot([:]))
      == .unknown)
  #expect(ContainerState.resolve(path: "/test.hc", exists: true, volumes: nil) == .unknown)
  #expect(
    ContainerState.resolve(path: "/test.hc", exists: true, volumes: VolumeSnapshot([:])) == .closed)
  #expect(
    ContainerState.resolve(
      path: "/test.hc", exists: true, volumes: VolumeSnapshot(["/test.hc": ""]))
      == .halfClosed
  )
  #expect(
    ContainerState.resolve(
      path: "/test.hc", exists: false, volumes: VolumeSnapshot(["/test.hc": "/Volumes/Test"]))
      == .open("/Volumes/Test"))
}

@Test func cancellationAndWorkingShareOneBarrier() {
  let cancelled = OperationChannel { _ in }
  #expect(cancelled.cancel())
  #expect(
    cancelled.receive(
      BackendMessage(kind: .working, text: "", detail: ""), response: nil, capacity: 0) == -1)
  let running = OperationChannel { _ in }
  #expect(
    running.receive(
      BackendMessage(kind: .working, text: "", detail: ""), response: nil, capacity: 0) == 0)
  #expect(!running.cancel())
  _ = running.receive(
    BackendMessage(kind: .ready, text: "", detail: ""), response: nil, capacity: 0)
  #expect(running.cancel())
  #expect(
    running.receive(
      BackendMessage(kind: .working, text: "", detail: ""), response: nil, capacity: 0) == -1)
}

@Test func successKeepsWarningsUntilTheUserCanReadThem() {
  let channel = OperationChannel { _ in }
  let warning = "Warning: created the container but could not close it."
  _ = channel.receive(
    BackendMessage(kind: .warning, text: warning, detail: ""), response: nil, capacity: 0)
  _ = channel.receive(
    BackendMessage(kind: .info, text: "Created", detail: ""), response: nil, capacity: 0)
  #expect(channel.result(0).warnings == [warning])
}

@Test func keyConnectionWaitsForContinueOrCancel() async {
  for cancel in [false, true] {
    let prompted = AsyncStream<Void>.makeStream()
    let channel = OperationChannel { _ in
      prompted.continuation.yield(())
      prompted.continuation.finish()
    }
    let waiting = Task.detached {
      var response = [UInt8](repeating: 0, count: 8)
      return response.withUnsafeMutableBufferPointer { buffer in
        channel.receive(
          BackendMessage(kind: .connect, text: "Connect the new key.", detail: ""),
          response: buffer.baseAddress, capacity: buffer.count)
      }
    }
    for await _ in prompted.stream { break }
    if cancel { _ = channel.cancel() } else { channel.respond("") }
    let result = await waiting.value
    #expect(result == (cancel ? -1 : 0))
  }
}

@Test func nulInAnArgumentCannotChangeWhichKeyIsNamed() async {
  let channel = OperationChannel { _ in }
  let result = await RustBackend.run(
    ["remove-key", "/unused.hc", "--label", "Backup\0Other"], channel: channel)
  #expect(result.code == 1)
  #expect(result.error != nil)
}

private actor KeyBackend {
  var labels = ["Main key", "Spare — café", "é", "e\u{301}"]
  var actions: [[String]] = []
  var failNextChange = false
  var open = false

  func failAndLeaveOpen() { failNextChange = true }

  func run(_ args: [String], _ channel: OperationChannel) -> BackendResult {
    switch args[0] {
    case "volumes":
      if open {
        _ = channel.receive(
          BackendMessage(kind: .volume, text: actions.last![1], detail: "/Volumes/Example"),
          response: nil, capacity: 0)
      }
    case "list-keys":
      for label in labels {
        _ = channel.receive(
          BackendMessage(kind: .keyLabel, text: label, detail: ""), response: nil, capacity: 0)
      }
    default:
      actions.append(args)
      if failNextChange {
        failNextChange = false
        open = true
        _ = channel.receive(
          BackendMessage(kind: .error, text: "The probe could not close.", detail: ""),
          response: nil, capacity: 0)
        return channel.result(1)
      }
      if args[0] == "add-key" { labels.append(args[3]) }
      if args[0] == "remove-key" {
        labels.removeAll { label in args.dropFirst(2).contains { $0.utf8.elementsEqual(label.utf8) }
        }
      }
    }
    return channel.result(0)
  }
}

@MainActor private func waitForKeys(_ model: AppModel) async throws {
  let deadline = ContinuousClock.now.advanced(by: .seconds(5))
  while (model.operation != nil || model.keyManager?.loading != false)
    && ContinuousClock.now < deadline
  {
    if model.operation?.completed == true { model.finishOperation() }
    try await Task.sleep(for: .milliseconds(10))
  }
  #expect(model.operation == nil && model.keyManager?.loading == false)
}

private func keyIDs(_ labels: [String]) -> Set<Data> { Set(labels.map { Data($0.utf8) }) }

@MainActor private func waitUntil(_ ready: () -> Bool) async throws {
  let deadline = ContinuousClock.now.advanced(by: .seconds(5))
  while !ready() && ContinuousClock.now < deadline {
    try await Task.sleep(for: .milliseconds(10))
  }
  #expect(ready())
}

@Test @MainActor func addKeyWizardShowsWhichKeyToUseAndWaitsForSuccess() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).hc")
  try Data("public test fixture".utf8).write(to: url)
  defer { try? FileManager.default.removeItem(at: url) }
  let saved = SavedContainer(url: url)
  let messages = AsyncStream<BackendMessage>.makeStream()
  let model = AppModel(defaults: defaults) { args, channel in
    if args[0] == "add-key" {
      for await message in messages.stream {
        if channel.receive(message, response: nil, capacity: 0) < 0 { return channel.result(2) }
      }
    } else if args[0] == "list-keys" {
      _ = channel.receive(
        BackendMessage(kind: .keyLabel, text: "Existing key", detail: ""), response: nil,
        capacity: 0)
    }
    return channel.result(0)
  }
  model.containers = [saved]
  model.showKeys(saved)
  try await waitForKeys(model)
  model.addKey("New key")
  #expect(model.operation?.heading == "Use an existing key")
  #expect(model.operation?.stepIndex == 0)
  messages.continuation.yield(
    BackendMessage(kind: .working, text: "Finishing an earlier change…", detail: ""))
  try await waitUntil { model.operation?.cancellable == false }
  #expect(model.operation?.stepIndex == 0)
  messages.continuation.yield(BackendMessage(kind: .ready, text: "", detail: ""))
  try await waitUntil { model.operation?.cancellable == true }
  for (step, index, heading) in [
    ("connect", 1, "Connect the new key"),
    ("enroll", 2, "Enroll the new key"),
    ("write", 3, "Save the new key"),
  ] {
    messages.continuation.yield(BackendMessage(kind: .step, text: step, detail: ""))
    try await waitUntil { model.operation?.stepIndex == index }
    #expect(model.operation?.heading == heading)
    #expect(model.operation?.completed == false)
    if step == "enroll" {
      messages.continuation.yield(
        BackendMessage(kind: .touch, text: "Touch the new key.", detail: ""))
      try await waitUntil { model.operation?.message == "Touch the new key." }
    }
  }
  #expect(model.operation?.message == "Checking the container…")
  messages.continuation.yield(
    BackendMessage(kind: .warning, text: "Public test warning", detail: ""))
  messages.continuation.finish()
  try await waitUntil { model.operation?.completed == true }
  #expect(model.operation?.heading == "Key added")
  #expect(model.operation?.detail == "Public test warning")
  #expect(model.operation?.prompt == nil && model.operation?.recovery.isEmpty == true)
  model.finishOperation()
  try await waitForKeys(model)
  #expect(model.keyManager?.container.id == saved.id)
}

@Test @MainActor func keyActionsPreserveNamesAndRefreshAccess() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).hc")
  try Data("public test fixture".utf8).write(to: url)
  defer { try? FileManager.default.removeItem(at: url) }
  let saved = SavedContainer(url: url)
  let backend = KeyBackend()
  let model = AppModel(defaults: defaults) { args, channel in await backend.run(args, channel) }
  model.containers = [saved]
  model.showKeys(saved)
  try await waitForKeys(model)
  #expect(model.keyManager?.labels == ["Main key", "Spare — café", "é", "e\u{301}"])
  #expect(Set(model.keyManager!.keys.map(\.id)).count == 4)
  #expect(model.canChangeKeys)
  model.removeKeys(keyIDs(["Main key", "Spare — café", "é", "e\u{301}"]))
  let initialActions = await backend.actions
  #expect(initialActions.isEmpty)
  model.addKey("  Travel key  ")
  try await waitForKeys(model)
  #expect(model.keyManager?.labels == ["Main key", "Spare — café", "é", "e\u{301}", "Travel key"])
  model.removeKeys(keyIDs(["Spare — café", "é"]))
  try await waitForKeys(model)
  #expect(
    model.keyManager?.labels.map { Data($0.utf8) }
      == ["Main key", "e\u{301}", "Travel key"].map { Data($0.utf8) })
  model.changeRecoveryPhrase()
  try await waitForKeys(model)
  let actions = await backend.actions
  #expect(
    actions == [
      ["add-key", saved.path, "--label", "Travel key"],
      ["remove-key", saved.path, "--label", "Spare — café", "--label", "é"],
      ["rotate", saved.path],
    ])
  await backend.failAndLeaveOpen()
  model.addKey("Another")
  try await waitForKeys(model)
  #expect(model.states[saved.id] == .open("/Volumes/Example"))
  #expect(!model.canChangeKeys)
  #expect(model.keyManager?.notice == "The probe could not close.")
  model.removeKeys(keyIDs(["Travel key"]))
  let afterFailure = await backend.actions
  #expect(afterFailure.count == actions.count + 1)
}

@Test func rememberedContainersSurviveRelaunchAndForgetKeepsTheFile() throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(suite)
  try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let url = folder.appendingPathComponent("Example.hc")
  try Data("public test fixture".utf8).write(to: url)
  var store = ContainerStore(defaults: defaults)
  #expect(try store.load().isEmpty)
  let saved = SavedContainer(url: url)
  try store.save([saved])
  #expect(try store.load() == [saved])
  try store.save([])
  #expect(try store.load().isEmpty)
  #expect(FileManager.default.fileExists(atPath: url.path))
}

@Test func movingAnOpenContainerPreservesItsClosePath() throws {
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let original = folder.appendingPathComponent("Original.hc")
  let moved = folder.appendingPathComponent("Moved.hc")
  try Data("public test fixture".utf8).write(to: original)
  var saved = SavedContainer(url: original)
  let originalPath = saved.path
  try FileManager.default.moveItem(at: original, to: moved)
  let volumes = VolumeSnapshot([originalPath: "/Volumes/Example"])
  #expect(saved.resolve(volumes: volumes).path == originalPath)
  #expect(
    ContainerState.resolve(path: saved.path, exists: false, volumes: volumes)
      == .open("/Volumes/Example"))
  #expect(saved.resolve(volumes: nil).path == originalPath)
  #expect(saved.resolve(volumes: VolumeSnapshot([:])).path == moved.resolvingSymlinksInPath().path)
}

@Test func backendPathsMatchTheSavedContainer() throws {
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let file = folder.appendingPathComponent("Example.hc")
  try Data("public test fixture".utf8).write(to: file)
  var saved = SavedContainer(url: file)
  let native = try #require(realpath(file.path, nil))
  defer { free(native) }
  let channel = OperationChannel { _ in }
  _ = channel.receive(
    BackendMessage(kind: .volume, text: String(cString: native), detail: "/Volumes/Example"),
    response: nil, capacity: 0)
  let volumes = VolumeSnapshot(channel.result(0).volumes)
  _ = saved.resolve(volumes: volumes)
  #expect(saved.path == String(cString: native))
  #expect(saved.matches(file.resolvingSymlinksInPath().standardizedFileURL.path))
  #expect(
    ContainerState.resolve(path: saved.path, exists: true, volumes: volumes)
      == .open("/Volumes/Example"))
}

@Test func reusedSourcePathKeepsTheOriginalAttachment() throws {
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let original = folder.appendingPathComponent("Original.hc")
  let moved = folder.appendingPathComponent("Moved.hc")
  let other = folder.appendingPathComponent("Other.hc")
  try Data("original fixture".utf8).write(to: original)
  try Data("other fixture".utf8).write(to: other)
  var saved = SavedContainer(url: original)
  let native = try #require(realpath(original.path, nil))
  defer { free(native) }
  let attachedPath = String(cString: native)
  try FileManager.default.moveItem(at: original, to: moved)
  try FileManager.default.createSymbolicLink(at: original, withDestinationURL: other)
  let channel = OperationChannel { _ in }
  _ = channel.receive(
    BackendMessage(kind: .volume, text: attachedPath, detail: "/Volumes/Original"),
    response: nil, capacity: 0)
  let volumes = VolumeSnapshot(channel.result(0).volumes)
  _ = saved.resolve(volumes: volumes)
  let state = ContainerState.resolve(path: saved.path, exists: true, volumes: volumes)
  #expect(saved.path == attachedPath)
  #expect(state == .open("/Volumes/Original"))
  #expect(!state.canForget)
  #expect(
    ContainerState.resolve(path: other.path, exists: true, volumes: volumes) == .closed)
  #expect(saved.resolve(volumes: VolumeSnapshot([:])).path == moved.resolvingSymlinksInPath().path)
}

@Test func conflictingAttachmentAliasesStayUnknown() {
  let channel = OperationChannel { _ in }
  for (path, mount) in [
    ("/var/fido2vc/Example.hc", "/Volumes/First"),
    ("/private/var/fido2vc/Example.hc", "/Volumes/Second"),
  ] {
    _ = channel.receive(
      BackendMessage(kind: .volume, text: path, detail: mount), response: nil, capacity: 0)
  }
  let state = ContainerState.resolve(
    path: "/var/fido2vc/Example.hc", exists: true,
    volumes: VolumeSnapshot(channel.result(0).volumes))
  #expect(state == .unknown)
  #expect(!state.canForget)
}

@Test func missingSourceParentKeepsItsAttachmentPath() throws {
  let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  let parent = folder.appendingPathComponent("Original")
  try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: folder) }
  let file = parent.appendingPathComponent("Example.hc")
  try Data("public fixture".utf8).write(to: file)
  var saved = SavedContainer(url: file)
  let native = try #require(realpath(file.path, nil))
  defer { free(native) }
  let attachedPath = String(cString: native)
  try FileManager.default.moveItem(at: parent, to: folder.appendingPathComponent("Moved"))
  let channel = OperationChannel { _ in }
  _ = channel.receive(
    BackendMessage(kind: .volume, text: attachedPath, detail: ""), response: nil, capacity: 0)
  let volumes = VolumeSnapshot(channel.result(0).volumes)
  _ = saved.resolve(volumes: volumes)
  #expect(saved.path == attachedPath)
  #expect(ContainerState.resolve(path: saved.path, exists: false, volumes: volumes) == .halfClosed)
}

@Test @MainActor func unreadableSavedRecordsSurviveAStartupFailure() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let valid = try JSONEncoder().encode(SavedContainer(url: URL(fileURLWithPath: "/Example.hc")))
  var data = Data("[".utf8)
  data.append(valid)
  data.append(Data(", {\"path\":\"/Missing-ID.hc\"}]".utf8))
  defaults.set(data, forKey: "containers")
  var store = ContainerStore(defaults: defaults)
  var refusedLoad = false
  do { _ = try store.load() } catch { refusedLoad = true }
  var refusedSave = false
  do { try store.save([]) } catch { refusedSave = true }
  #expect(refusedLoad && refusedSave)
  for code in [Int32(0), Int32(1)] {
    let model = AppModel(defaults: defaults) { _, channel in channel.result(code) }
    #expect(model.statusError != nil)
    #expect(model.needsQuitWarning)
    await model.refreshStatus()
    #expect(model.statusError != nil)
    #expect(defaults.data(forKey: "containers") == data)
  }
}

@Test @MainActor func keyNameLimitCountsUTF8Bytes() throws {
  let options = CreateOptions()
  let validator = NewContainerValidator(options: options)
  let url = FileManager.default.temporaryDirectory.appendingPathComponent("\(UUID()).hc")
  options.label = String(repeating: "é", count: 128)
  try validator.panel(NSObject(), validate: url)
  options.label += "a"
  var refused = false
  do { try validator.panel(NSObject(), validate: url) } catch { refused = true }
  #expect(refused)
}

@Test @MainActor func aReadOnlyRefreshDoesNotBlockQuit() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let started = AsyncStream<Void>.makeStream()
  let finish = AsyncStream<Void>.makeStream()
  let model = AppModel(defaults: defaults) { _, channel in
    started.continuation.yield(())
    started.continuation.finish()
    for await _ in finish.stream { break }
    // A late callback remains valid while the query's task owns its channel.
    _ = channel.receive(
      BackendMessage(kind: .info, text: "Status received", detail: ""), response: nil, capacity: 0)
    return channel.result(0)
  }
  let refresh = Task { await model.refreshStatus() }
  for await _ in started.stream { break }
  #expect(model.refreshing)
  #expect(!model.busy)
  #expect(model.needsQuitWarning)
  #expect(!model.shouldQuit { false })
  #expect(model.shouldQuit { true })
  finish.continuation.yield(())
  finish.continuation.finish()
  await refresh.value
  #expect(!model.refreshing)
  #expect(!model.needsQuitWarning)
}

@Test @MainActor func duplicateSavedIDsPreserveTheOriginalRecords() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let saved = SavedContainer(url: URL(fileURLWithPath: "/Example.hc"))
  let original = try JSONEncoder().encode([saved, saved])
  defaults.set(original, forKey: "containers")
  let model = AppModel(defaults: defaults) { _, channel in channel.result(0) }
  await model.refreshStatus()
  #expect(model.statusError != nil)
  #expect(model.needsQuitWarning)
  #expect(defaults.data(forKey: "containers") == original)
}

@Test @MainActor func quitDecisionRechecksWorkStartedDuringConfirmation() async throws {
  let suite = "Fido2VC-test-\(UUID())"
  let defaults = try #require(UserDefaults(suiteName: suite))
  defer { defaults.removePersistentDomain(forName: suite) }
  let saved = SavedContainer(url: URL(fileURLWithPath: "/Example.hc"))
  let model = AppModel(defaults: defaults) { _, channel in channel.result(0) }
  model.containers = [saved]
  #expect(
    !model.shouldQuit {
      model.open(saved)
      return true
    })
  #expect(model.busy)
  // A requested query must count as pending before its task gets a chance to run.
  let statusModel = AppModel(defaults: defaults) { _, channel in channel.result(0) }
  statusModel.refresh()
  #expect(statusModel.refreshing)
  #expect(!statusModel.shouldQuit { false })
  let deadline = ContinuousClock.now.advanced(by: .seconds(5))
  while (model.busy || model.refreshing || statusModel.refreshing) && ContinuousClock.now < deadline
  {
    try await Task.sleep(for: .milliseconds(10))
  }
  #expect(!model.busy && !model.refreshing && !statusModel.refreshing)
}
