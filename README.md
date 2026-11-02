# fido2veracrypt

fido2veracrypt opens VeraCrypt containers with a FIDO2 security key, on macOS and Linux.

A container stays a normal VeraCrypt container. A random passphrase opens it, and each enrolled key wraps that passphrase in a slot file beside the container. Opening a container takes the key's PIN and a touch. The passphrase is also your recovery passphrase: you write it down once, and plain VeraCrypt opens the container with it on any system, Windows included.

The main use is a USB drive whose data must stay readable on both systems. Someone who steals the drive, even together with an enrolled key, gets only ciphertext while they do not know the key's PIN. The key blocks its PIN after 8 wrong tries.

## Requirements

- macOS on Apple silicon, or Linux.
- VeraCrypt 1.26.30 or later. Earlier versions are refused: on macOS, 1.26.30 fixes a FUSE-T dismount that could leave a volume readable.
  - macOS: `brew install --cask veracrypt-fuse-t`.
  - Linux: the package for your distribution from the VeraCrypt website, and `exfatprogs`.
- A FIDO2 security key with hmac-secret and a PIN, of any brand. Keys without a PIN cannot open containers. Set a PIN with the vendor's tool.

### FUSE-T mount timeouts on macOS

If VeraCrypt reports `The operation did not finish in time`, add this setting to `~/.fuse-t/fuse-t.ini`, preserving any existing settings:

```ini
[Default]
bonjour=false
```

FUSE-T then connects directly to localhost instead of using Bonjour discovery. This setting applies to your user's FUSE-T mounts. It works around the [SMB discovery issue](https://github.com/macos-fuse-t/fuse-t/issues/116).

## Mac app

Fido2VC provides Create, Open, and Close in a native Mac window. It requires macOS 14 or later and the requirements above.

1. Open **Fido2VC.app** and choose **Create**. Pick a location, size, and key name.
2. Enter the key's PIN in the app and touch the key when prompted.
3. Write down the recovery phrase and confirm its last group. Creation can take a few minutes.
4. Choose **Open**, then **Show Files** to use the container in Finder.
5. Choose **Close** before unplugging the drive.

The app remembers containers between launches. **Open** also adds an existing container. Close a container before moving or copying it, and keep its `.fido2veracrypt_meta` file beside it. **Forget Container** removes the remembered entry and keeps the files.

The menu bar icon shows the status of your saved containers and returns you to the window. Closing the window leaves the app in the menu bar. Quitting the app or removing the key does not close a container.

This first app version supports creation, opening, and closing. Use the CLI below to enroll extra keys, recover a lost key, or change a passphrase.

### Build the app

Install Rust and Xcode with Swift 6 or later, then run:

```sh
./macos/build.sh
open dist/Fido2VC.app
```

The build creates an ad-hoc-signed local app. Move it to Applications for daily use. It does not install VeraCrypt or FUSE-T.

Run the Swift workflow tests after building the Rust library with `swift test --package-path macos`. Regenerate the Dock and menu bar icons with `swift macos/Assets/make-icons.swift macos/Assets`.

## CLI usage

```text
fido2veracrypt opens VeraCrypt containers with a FIDO2 security key.

Usage: fido2veracrypt <command> [options]

Commands:
  create <container> --size <size> --label <label>
      Make a container and enroll the plugged-in key under <label>.
  adopt <container> --label <label>
      Enroll a key for an existing container and give it a new passphrase.
  open <container>
      Unlock and mount a container.
  close [<container>] [--force]
      Unmount a container, or every open one. On macOS, --force closes it even with files
      open, and unsaved changes in them are lost.
  add-key <container> --label <label> [--recovery]
      Enroll another key. --recovery uses the recovery passphrase and rebuilds the slot file.
  remove-key <container> --label <label>...
      Remove lost or stolen keys and change the passphrase.
  rotate <container>
      Change the passphrase and show the new one.
  status [<container>]
      Show the open volumes, or one container's keys and state.
  list-keys <container>
      List the enrolled keys.
  completions zsh|bash
      Print the shell completion script.
  help
      Show this text.

Sizes take a K, M, G, or T suffix, in powers of 1024.
```

`create` makes an exFAT container that both systems read and write, with AES-256 and Argon2 key derivation, and labels it with the container's name, cut to 11 characters. On macOS it opens at `/Volumes/<label>`. On Linux, VeraCrypt opens it at `/media/veracryptN`.

Container paths must be UTF-8 and cannot contain NUL or line breaks. Key names take at most 256 UTF-8 bytes. A `.fido2veracrypt_lock` file beside the container coordinates commands from different windows. It contains no secrets. Leave it in place while any command uses the container.

### Unlocking

With several keys plugged in, all of them blink: touch the one to use. Then enter its PIN and touch it again. With one key, the first touch is skipped.

### The recovery passphrase

`create`, `adopt`, `rotate`, and `remove-key` show a new recovery passphrase on the terminal: 52 characters in groups of 4. It never goes to stdout, so a redirect cannot save it. Write it down, keep it away from the drive, and type its last group back when asked. The new passphrase is not written until you confirm it.

To open the container without fido2veracrypt, give VeraCrypt the passphrase exactly as printed, dashes included. If every key is lost or the slot file is gone, `add-key --recovery` enrolls a key again from the printout.

Recovery keeps an existing slot file in a uniquely named `.replaced-…` backup. An interrupted passphrase change retains both stored values until the header is checked. If a retry still fails, Open can use the verified old value, but key changes and further rotations wait until the pending change finishes.

### Closing

Close a volume with `fido2veracrypt close` before you pull the drive. If a program still has a file open on it, close that program first. `close --force` closes anyway on macOS, and unsaved changes are lost. Linux cannot close a volume with open files even then, so there close the program, which `fuser -vm <mount point>` names. Ejecting it in Finder unmounts the filesystem but leaves VeraCrypt holding the volume, still unlocked. `status` shows such a volume as half closed, and `close` finishes the job.

If the source folder moved or disappeared, name the original attached path with `close <path>`. Close-all cannot identify a managed container when its source and slot file are unavailable, so it reports that uncertainty.

## Linux

VeraCrypt needs root on Linux to open and close volumes. Without further setup, fido2veracrypt runs it through `sudo`, which asks for your password.

To open and close without a password, install the helper. It runs VeraCrypt as root with fixed options, mounts only exFAT, and acts only on containers that have a slot file beside them, so the sudoers rule cannot be used to run VeraCrypt with other options. Do not give your user a password-free rule for `veracrypt` itself: its `--token-lib` option loads any library, so that rule is root for every process you run.

```sh
cargo build --release
sudo install -o root -g root -m 0755 target/release/fido2veracrypt-helper /usr/local/libexec/fido2veracrypt-helper
echo "$USER ALL=(root) NOPASSWD: /usr/local/libexec/fido2veracrypt-helper" > /tmp/fido2veracrypt.sudoers
sudo visudo -cf /tmp/fido2veracrypt.sudoers && sudo install -o root -g root -m 0440 /tmp/fido2veracrypt.sudoers /etc/sudoers.d/fido2veracrypt
```

`create` still asks for your sudo password, because it formats the volume as root. So do `adopt` and `add-key --recovery`, because the helper refuses a container that has no slot file yet.

The helper checks its fixed `/usr/bin/veracrypt` version before each action. If the client selects a different VeraCrypt executable, it uses that executable through sudo instead of the helper.

## Limits

- A passphrase change rewrites only the container's header. Any copy of the container made before the change still opens with the old passphrase. For full revocation, create a new container and copy the files over.
- The key protects the container while it is closed. While a volume is open, root and any program running as you can read it.
- Labels and metadata in the slot file are checked against a tag on every unlock. A slot file changed by someone else stops every command with an error and changes nothing.

## License

Copyright 2026 Jessica Cox <jmcox@posteo.de>

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
