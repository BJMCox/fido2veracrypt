import SwiftUI

struct MainView: View {
  @ObservedObject var model: AppModel

  var body: some View {
    VStack(spacing: 0) {
      HStack(spacing: 12) {
        Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 38, height: 38)
        VStack(alignment: .leading, spacing: 3) {
          Text("Your containers").font(.title2.weight(.semibold))
          Text("Open with your key. Use your files in Finder.").font(.callout).foregroundStyle(
            .secondary)
        }
        Spacer()
        Button("Open…", action: model.openPicker).keyboardShortcut("o")
        Button("Create…", action: model.createPicker).keyboardShortcut("n").buttonStyle(
          .borderedProminent)
      }
      .padding(22)
      .disabled(model.busy || model.refreshing)
      Divider()
      if model.containers.isEmpty {
        VStack(spacing: 14) {
          Image(systemName: "lock.shield").font(.system(size: 52, weight: .light)).foregroundStyle(
            .secondary)
          Text("A home for your private files").font(.title2.weight(.medium))
          Text("Create an encrypted container on a drive,\nor open one you already use.")
            .multilineTextAlignment(.center).foregroundStyle(.secondary)
          Button("Create a Container…", action: model.createPicker).controlSize(.large)
            .buttonStyle(.borderedProminent).padding(.top, 4).disabled(
              model.busy || model.refreshing)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else {
        ScrollView {
          LazyVStack(spacing: 0) {
            ForEach(model.containers) { container in
              ContainerRow(
                container: container, state: model.states[container.id, default: .unknown],
                model: model)
              if container.id != model.containers.last?.id { Divider().padding(.leading, 68) }
            }
          }
          .padding(.vertical, 8)
        }
      }
      if let error = model.statusError {
        HStack(alignment: .top) {
          Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
          Text(error).font(.callout).textSelection(.enabled)
          Spacer(minLength: 4)
          Button("Retry", action: model.refresh).disabled(model.busy || model.refreshing)
        }
        .padding(16).background(.orange.opacity(0.08))
      }
      Divider()
      HStack(spacing: 7) {
        Image(systemName: "info.circle")
        Text("Close your containers before unplugging the drive.")
        Spacer()
        if model.refreshing {
          ProgressView().controlSize(.small).accessibilityLabel("Checking container status")
        }
        Button(action: model.refresh) { Image(systemName: "arrow.clockwise") }
          .buttonStyle(.plain).help("Refresh status").accessibilityLabel("Refresh status")
          .disabled(model.busy || model.refreshing)
      }
      .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 20).padding(.vertical, 13)
    }
    .frame(minWidth: 640, minHeight: 400)
    .sheet(item: $model.operation) { _ in OperationView(model: model).interactiveDismissDisabled() }
    .alert(
      "Fido2VC",
      isPresented: Binding(get: { model.alert != nil }, set: { if !$0 { model.alert = nil } })
    ) {
      Button("OK", role: .cancel) { model.alert = nil }
    } message: {
      Text(model.alert ?? "")
    }
  }
}

private struct ContainerRow: View {
  let container: SavedContainer
  let state: ContainerState
  @ObservedObject var model: AppModel

  var body: some View {
    HStack(spacing: 16) {
      Image(systemName: "externaldrive")
        .font(.system(size: 28)).foregroundStyle(state.isOpen ? Color.green : Color.secondary)
        .frame(width: 36)
      VStack(alignment: .leading, spacing: 5) {
        HStack {
          Text(container.name).font(.headline)
          Text(state.label).font(.caption.weight(.medium))
            .foregroundStyle(state.isOpen ? Color.green : Color.secondary)
        }
        Text(container.url.deletingLastPathComponent().path).font(.caption).foregroundStyle(
          .secondary
        ).lineLimit(1).truncationMode(.middle)
        if state == .halfClosed {
          Text("Finder ejected the files. Close the container to finish locking it.").font(.caption)
            .foregroundStyle(.orange)
        }
      }
      Spacer(minLength: 12)
      switch state {
      case .open(let path):
        Button("Show Files") { model.showFiles(path) }
        Button("Close") { model.close(container) }
      case .halfClosed:
        Button("Close") { model.close(container) }.buttonStyle(.borderedProminent)
      case .closed:
        Button("Open") { model.open(container) }.buttonStyle(.borderedProminent)
      case .unknown:
        Button("Check", action: model.refresh)
        Button("Close") { model.close(container) }
      case .unavailable:
        Text("Connect the drive").font(.callout).foregroundStyle(.secondary)
      }
      Menu {
        Button("Show Container in Finder") {
          NSWorkspace.shared.activateFileViewerSelecting([container.url])
        }
        Button("Forget Container") { model.forget(container) }.disabled(!state.canForget)
      } label: {
        Image(systemName: "ellipsis.circle")
      }
      .menuStyle(.borderlessButton).fixedSize().help("Container options")
      .accessibilityLabel("Options for \(container.name)")
    }
    .padding(.horizontal, 22).padding(.vertical, 18)
    .disabled(model.busy || model.refreshing)
  }
}

struct OperationView: View {
  @ObservedObject var model: AppModel
  @State private var answer = ""
  @FocusState private var inputFocused: Bool

  private var canSubmit: Bool {
    guard let operation = model.operation, answer.utf8.count < 4096 else { return false }
    if operation.prompt == .confirmation {
      let normalized = answer.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        .replacingOccurrences(of: "I", with: "1").replacingOccurrences(of: "L", with: "1")
        .replacingOccurrences(of: "O", with: "0")
      return normalized == operation.recovery.split(separator: "-").last.map(String.init)
    }
    return !answer.isEmpty
  }

  var body: some View {
    if let operation = model.operation {
      VStack(alignment: .leading, spacing: 18) {
        HStack(spacing: 13) {
          Image(systemName: operation.prompt == .confirmation ? "key.horizontal" : "lock.shield")
            .font(.system(size: 28)).foregroundStyle(.tint)
          Text(operation.title).font(.title2.weight(.semibold))
        }
        Text(operation.message).font(.headline)
        if operation.prompt == .confirmation {
          Text(
            "Write this down and keep it away from the drive. It opens the container if you lose your key."
          )
          .foregroundStyle(.secondary)
          Text(operation.recovery).font(.system(.body, design: .monospaced)).lineSpacing(5)
            .fixedSize(horizontal: false, vertical: true).padding(14)
            .frame(maxWidth: .infinity, alignment: .leading).background(
              .quaternary, in: RoundedRectangle(cornerRadius: 8)
            )
            .privacySensitive()
          TextField("Last group of the phrase", text: $answer).focused($inputFocused)
            .textFieldStyle(.roundedBorder).frame(width: 210).privacySensitive()
            .onSubmit(submit).accessibilityIdentifier("recovery-confirmation")
        } else if operation.prompt == .pin {
          if !operation.detail.isEmpty {
            Text(operation.detail).font(.callout).foregroundStyle(.secondary)
          }
          SecureField("Security key PIN", text: $answer).focused($inputFocused)
            .textFieldStyle(.roundedBorder).onSubmit(submit).privacySensitive()
            .accessibilityIdentifier("security-key-pin")
        } else {
          HStack(spacing: 12) {
            ProgressView().controlSize(.small)
            Text(operation.detail).font(.callout).foregroundStyle(.secondary)
          }
        }
        HStack {
          Spacer()
          if operation.cancellable {
            Button("Cancel") {
              answer = ""
              model.cancel()
            }.keyboardShortcut(.cancelAction)
          }
          if operation.prompt != nil {
            Button(
              operation.prompt == .confirmation ? "Create Container" : "Continue", action: submit
            )
            .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(!canSubmit)
          }
        }
      }
      .padding(28).frame(width: 470)
      .onChange(of: operation.prompt) { _, _ in
        answer = ""
        inputFocused = true
      }
      .onAppear { inputFocused = true }
      .onDisappear { answer = "" }
    }
  }

  private func submit() {
    guard canSubmit else { return }
    let response = answer
    answer = ""
    model.respond(response)
  }
}

struct CreateOptionsView: View {
  @ObservedObject var options: CreateOptions
  var body: some View {
    Form {
      HStack {
        Text("Size")
        TextField("Size", text: $options.size).labelsHidden().frame(width: 70)
          .accessibilityIdentifier(
            "container-size")
        Picker("Unit", selection: $options.unit) {
          Text("GiB").tag("G")
          Text("MiB").tag("M")
        }.labelsHidden().frame(width: 90)
      }
      TextField("Key name", text: $options.label).accessibilityIdentifier("key-name")
    }
    .padding(14)
  }
}
