#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
APP=build/Payload/IPQuery.app
rm -rf build IPQuery.ipa
mkdir -p "$APP"

for ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$ARCH" \
        -isysroot "$SDK" \
        -miphoneos-version-min=14.0 \
        -fobjc-arc \
        -fblocks \
        -O2 \
        -framework Foundation \
        -framework UIKit \
        -framework CoreFoundation \
        main.m \
        -o "build/IPQuery_${ARCH}"
done
lipo -create build/IPQuery_arm64 build/IPQuery_arm64e -output "$APP/IPQuery"
cp Info.plist "$APP/Info.plist"
printf 'APPL????' > "$APP/PkgInfo"

codesign --force --sign - --timestamp=none "$APP"
codesign --verify --strict "$APP"
(cd build && zip -qr ../IPQuery.ipa Payload)
echo "OK $(pwd)/IPQuery.ipa"
unzip -l IPQuery.ipa
