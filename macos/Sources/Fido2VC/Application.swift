import AppKit
import Combine
import SwiftUI

@main
enum Fido2VCApplication {
  @MainActor static func main() {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.regular)
    withExtendedLifetime(delegate) { app.run() }
  }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
  let model = AppModel()
  private var window: NSWindow!
  private var workspaceObservers: [NSObjectProtocol] = []
  private var statusItem: NSStatusItem?
  private var statusSummary: NSMenuItem?
  private var statusActions: [NSMenuItem] = []
  private var statusObserver: AnyCancellable?

  func applicationDidFinishLaunching(_ notification: Notification) {
    if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
      let image = NSImage(contentsOf: url)
    {
      NSApp.applicationIconImage = image
    }
    window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 730, height: 470),
      styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false
    )
    window.title = "Fido2VC"
    window.minSize = NSSize(width: 660, height: 420)
    window.isReleasedWhenClosed = false
    window.delegate = self
    window.contentViewController = NSHostingController(rootView: MainView(model: model))
    window.center()
    model.window = window
    makeMenu()
    makeStatusItem()
    showWindow()
    let center = NSWorkspace.shared.notificationCenter
    for name in [
      NSWorkspace.didMountNotification, NSWorkspace.didUnmountNotification,
      NSWorkspace.didRenameVolumeNotification,
    ] {
      workspaceObservers.append(
        center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
          Task { @MainActor in self?.model.refresh() }
        })
    }
    model.refresh()
  }

  func applicationDidBecomeActive(_ notification: Notification) { model.refresh() }

  func application(_ application: NSApplication, open urls: [URL]) {
    showWindow()
    guard urls.count == 1 else {
      model.alert = "Open one container at a time."
      return
    }
    if let url = urls.first { model.addAndOpen(url) }
  }

  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool
  {
    showWindow()
    return true
  }

  func windowShouldClose(_ sender: NSWindow) -> Bool {
    if model.busy {
      NSSound.beep()
      return false
    }
    return true
  }

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    if model.busy {
      showWindow()
      NSSound.beep()
      return .terminateCancel
    }
    // A status query is read-only. Its task keeps the callback context alive until
    // Rust returns; quitting must not cancel or free that context early.
    let allowed = model.shouldQuit {
      let alert = NSAlert()
      alert.messageText = "Quitting does not close containers."
      alert.informativeText =
        "Close containers first. Removing the key does not close them."
      alert.addButton(withTitle: "Cancel")
      alert.addButton(withTitle: "Quit and Leave Open")
      return alert.runModal() == .alertSecondButtonReturn
    }
    return allowed ? .terminateNow : .terminateCancel
  }

  @objc private func showWindow() {
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }
  @objc private func create() {
    showWindow()
    model.createPicker()
  }
  @objc private func open() {
    showWindow()
    model.openPicker()
  }
  @objc private func refresh() { model.refresh() }

  private func makeStatusItem() {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    let image =
      Bundle.main.url(forResource: "MenuBarIcon", withExtension: "pdf").flatMap(
        NSImage.init(contentsOf:))
      ?? NSImage(systemSymbolName: "archivebox", accessibilityDescription: "Fido2VC")
    image?.size = NSSize(width: 22, height: 22)
    image?.isTemplate = true
    item.button?.image = image
    item.button?.setAccessibilityLabel("Fido2VC")
    let menu = NSMenu()
    statusSummary = menu.addItem(
      withTitle: "Checking container status…", action: nil, keyEquivalent: "")
    menu.addItem(.separator())
    let show = menu.addItem(
      withTitle: "Show Containers", action: #selector(showWindow), keyEquivalent: "")
    show.target = self
    for (title, action) in [
      ("Create Container…", #selector(create)), ("Open Container…", #selector(open)),
    ] {
      let entry = menu.addItem(withTitle: title, action: action, keyEquivalent: "")
      entry.target = self
      statusActions.append(entry)
    }
    menu.addItem(.separator())
    let quit = menu.addItem(
      withTitle: "Quit Fido2VC", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    quit.target = NSApp
    menu.autoenablesItems = false
    item.menu = menu
    statusItem = item
    statusObserver = model.objectWillChange.sink { [weak self] in
      DispatchQueue.main.async { self?.updateStatusItem() }
    }
    updateStatusItem()
  }

  private func updateStatusItem() {
    let count = model.states.values.filter(\.isOpen).count
    let status: String
    if let operation = model.operation {
      status = operation.message
    } else if model.refreshing {
      status = "Checking container status…"
    } else if model.statusError != nil {
      status = "Container status unknown"
    } else if model.containers.isEmpty {
      status = "No saved containers"
    } else if count == 0 {
      status = "No saved containers open"
    } else {
      status = "\(count) of \(model.containers.count) containers open"
    }
    statusSummary?.title = status
    statusSummary?.isEnabled = false
    statusItem?.button?.toolTip = "Fido2VC — \(status)"
    for item in statusActions { item.isEnabled = !model.busy && !model.refreshing }
  }

  private func makeMenu() {
    let menu = NSMenu()
    let appItem = NSMenuItem()
    let appMenu = NSMenu()
    appMenu.addItem(
      withTitle: "About Fido2VC", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
      keyEquivalent: "")
    appMenu.addItem(.separator())
    appMenu.addItem(
      withTitle: "Hide Fido2VC", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
    appMenu.addItem(.separator())
    appMenu.addItem(
      withTitle: "Quit Fido2VC", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    appItem.submenu = appMenu
    menu.addItem(appItem)
    let fileItem = NSMenuItem()
    let fileMenu = NSMenu(title: "File")
    for (title, action, key) in [
      ("Create Container…", #selector(create), "n"), ("Open Container…", #selector(open), "o"),
      ("Refresh Status", #selector(refresh), "r"), ("Show Containers", #selector(showWindow), "0"),
    ] {
      let item = fileMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
      item.target = self
    }
    fileItem.submenu = fileMenu
    menu.addItem(fileItem)
    let editItem = NSMenuItem()
    let editMenu = NSMenu(title: "Edit")
    for (title, action, key) in [
      ("Cut", #selector(NSText.cut(_:)), "x"), ("Copy", #selector(NSText.copy(_:)), "c"),
      ("Paste", #selector(NSText.paste(_:)), "v"),
      ("Select All", #selector(NSText.selectAll(_:)), "a"),
    ] {
      editMenu.addItem(withTitle: title, action: action, keyEquivalent: key)
    }
    editItem.submenu = editMenu
    menu.addItem(editItem)
    NSApp.mainMenu = menu
  }
}
