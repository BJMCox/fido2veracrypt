import SwiftUI

struct KeyManagerView: View {
  @ObservedObject var model: AppModel
  @State private var name = ""
  @State private var selected: Set<Data> = []
  @State private var confirmRemoval = false

  var body: some View {
    if let manager = model.keyManager {
      VStack(alignment: .leading, spacing: 16) {
        Text("Keys for \(manager.container.name)").font(.title2.weight(.semibold))
        if manager.loading {
          HStack {
            ProgressView().controlSize(.small)
            Text("Reading keys…")
          }.frame(height: 180)
        } else if let error = manager.error {
          Text(error).textSelection(.enabled).foregroundStyle(.orange)
        } else {
          List(manager.keys, selection: $selected) { key in
            Label(key.name, systemImage: "key.horizontal").tag(key.id)
          }
          .frame(height: 170)
          .accessibilityLabel("Enrolled keys")
          HStack {
            Text("Select keys to remove.").font(.caption).foregroundStyle(.secondary)
            Spacer()
            Button("Remove…") { confirmRemoval = true }
              .disabled(
                !model.canChangeKeys || selected.isEmpty || selected.count >= manager.labels.count)
          }
          Text("Names are unverified until you use a key.")
            .font(.caption).foregroundStyle(.secondary)
          if selected.count == manager.labels.count && !selected.isEmpty {
            Text("The last key cannot be removed.").font(.callout).foregroundStyle(.orange)
          }
          if !model.canChangeKeys {
            Text("Close the container before changing keys.").font(.callout)
          }
          Divider()
          HStack {
            TextField("New key name", text: $name).textFieldStyle(.roundedBorder)
              .accessibilityIdentifier("new-key-name")
            Button("Add Key…") { model.addKey(name) }.disabled(!model.canAddKey(name))
          }
        }
        if let notice = manager.notice {
          Text(notice).font(.callout).textSelection(.enabled)
        }
        HStack {
          Button("Change Recovery Phrase…", action: model.changeRecoveryPhrase)
            .disabled(!model.canChangeKeys)
          Spacer()
          Button("Done", action: model.dismissKeys).keyboardShortcut(.cancelAction)
            .disabled(manager.loading)
        }
      }
      .padding(24).frame(width: 490)
      .confirmationDialog("Remove the selected keys?", isPresented: $confirmRemoval) {
        Button("Remove Keys", role: .destructive) { model.removeKeys(selected) }
      } message: {
        Text("You need every key you keep. This changes the recovery phrase.")
      }
    }
  }
}
