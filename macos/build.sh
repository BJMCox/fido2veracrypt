#!/bin/sh
set -eu
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"
export CARGO_TARGET_DIR="$repo_root/target"
export MACOSX_DEPLOYMENT_TARGET=14.0
cargo build --release --locked --lib
# SwiftPM does not track changes to a library supplied through the module map.
if [ target/release/libfido2veracrypt.a -nt macos/.build/release/Fido2VC ]; then
    rm -f macos/.build/release/Fido2VC
fi
swift build --package-path macos -c release "$@"
app="$repo_root/dist/Fido2VC.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp macos/.build/release/Fido2VC "$app/Contents/MacOS/Fido2VC"
cp macos/Info.plist "$app/Contents/Info.plist"
cp macos/Assets/AppIcon.icns macos/Assets/MenuBarIcon.pdf "$app/Contents/Resources/"
cp LICENSE NOTICE "$app/Contents/Resources/"
codesign --force --sign - "$app"
codesign --verify --strict "$app"
printf '%s\n' "$app"
