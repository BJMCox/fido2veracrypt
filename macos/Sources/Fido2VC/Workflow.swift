enum WorkflowStep: String, Sendable {
  case authenticate, connect, enroll, recovery, write
}

enum Workflow: String, Sendable {
  case create
  case addKey = "add-key"
  case removeKeys = "remove-key"
  case changePhrase = "rotate"

  var steps: [WorkflowStep] {
    switch self {
    case .create: [.enroll, .recovery, .write]
    case .addKey: [.authenticate, .connect, .enroll, .write]
    case .removeKeys, .changePhrase: [.authenticate, .recovery, .write]
    }
  }

  func title(for step: WorkflowStep) -> String {
    switch step {
    case .authenticate:
      self == .removeKeys ? "Use the keys you're keeping" : "Use an existing key"
    case .connect: "Connect the new key"
    case .enroll: self == .addKey ? "Enroll the new key" : "Enroll your key"
    case .recovery: self == .create ? "Save the recovery phrase" : "Save the new recovery phrase"
    case .write:
      switch self {
      case .create: "Create the container"
      case .addKey: "Save the new key"
      case .removeKeys: "Remove the selected keys"
      case .changePhrase: "Change the recovery phrase"
      }
    }
  }

  var outcome: String {
    switch self {
    case .create: "Container created"
    case .addKey: "Key added"
    case .removeKeys: "Keys removed"
    case .changePhrase: "Recovery phrase changed"
    }
  }

  var resultMessage: String {
    switch self {
    case .create: "Open the container to use it."
    case .addKey: "The new key can now open this container."
    case .removeKeys: "Use a remaining key or the new recovery phrase."
    case .changePhrase: "Use the new phrase for recovery. Your keys still work."
    }
  }
}
