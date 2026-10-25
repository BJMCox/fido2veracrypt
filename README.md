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

## Usage

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
      Unmount a container, or every open one. --force closes it even with files open, and
      unsaved changes in them are lost.
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

### Unlocking

With several keys plugged in, all of them blink: touch the one to use. Then enter its PIN and touch it again. With one key, the first touch is skipped.

### The recovery passphrase

`create`, `adopt`, `rotate`, and `remove-key` show a new recovery passphrase on the terminal before they change anything: 52 characters in groups of 4. It never goes to stdout, so a redirect cannot save it. Write it down, keep it away from the drive, and type its last group back when asked. Nothing is written until you do.

To open the container without fido2veracrypt, give VeraCrypt the passphrase exactly as printed, dashes included. If every key is lost or the slot file is gone, `add-key --recovery` enrolls a key again from the printout.

### Closing

Close a volume with `fido2veracrypt close` before you pull the drive. Ejecting it in Finder unmounts the filesystem but leaves VeraCrypt holding the volume, still unlocked. `status` shows such a volume as half closed, and `close` finishes the job.

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

## Limits

- A passphrase change rewrites only the container's header. Any copy of the container made before the change still opens with the old passphrase. For full revocation, create a new container and copy the files over.
- The key protects the container while it is closed. While a volume is open, root and any program running as you can read it.
- Labels and metadata in the slot file are checked against a tag on every unlock. A slot file changed by someone else stops every command with an error and changes nothing.

## License

Copyright 2026 Jessica Cox <jmcox@posteo.de>

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
