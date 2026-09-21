#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VER="1.2"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
COMMON=(-isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -fblocks
        -Werror=return-type -Werror=implicit-function-declaration)
FW=(-framework Foundation -framework UIKit)
mkdir -p build dist

for ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$ARCH" "${COMMON[@]}" "${FW[@]}" \
        -dynamiclib -install_name @rpath/NDLoginProbe.dylib \
        NDLoginProbe.m -o "build/NDLoginProbe_${ARCH}.dylib"
done

lipo -create build/NDLoginProbe_arm64.dylib build/NDLoginProbe_arm64e.dylib \
    -output dist/NDLoginProbe.dylib
codesign --force --sign - --timestamp=none dist/NDLoginProbe.dylib
codesign --verify --strict dist/NDLoginProbe.dylib
lipo -info dist/NDLoginProbe.dylib
otool -hv dist/NDLoginProbe.dylib
(cd dist && shasum -a 256 NDLoginProbe.dylib > SHA256SUMS.txt)
cat dist/SHA256SUMS.txt
echo "OK dist/NDLoginProbe.dylib"
