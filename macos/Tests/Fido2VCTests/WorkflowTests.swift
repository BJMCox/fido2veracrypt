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
