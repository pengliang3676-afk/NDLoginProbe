#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
COMMON=(-isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -fblocks
        -Werror=return-type -Werror=implicit-function-declaration)
ND_FW=(-framework Foundation -framework UIKit)
BDS_FW=(-framework Foundation -framework UIKit -framework WebKit)
mkdir -p build dist

build_one() {
    local src="$1" name="$2"
    shift 2
    local fw=("$@")
    for ARCH in arm64 arm64e; do
        xcrun --sdk iphoneos clang -arch "$ARCH" "${COMMON[@]}" "${fw[@]}" \
            -dynamiclib -install_name "@rpath/${name}.dylib" \
            "$src" -o "build/${name}_${ARCH}.dylib"
    done
    lipo -create "build/${name}_arm64.dylib" "build/${name}_arm64e.dylib" \
        -output "dist/${name}.dylib"
    codesign --force --sign - --timestamp=none "dist/${name}.dylib"
    codesign --verify --strict "dist/${name}.dylib"
    lipo -info "dist/${name}.dylib"
    otool -hv "dist/${name}.dylib"
}

build_one NDLoginProbe.m NDLoginProbe "${ND_FW[@]}"
build_one BDSLoginProbe.m BDSLoginProbe "${BDS_FW[@]}"

(cd dist && shasum -a 256 NDLoginProbe.dylib BDSLoginProbe.dylib > SHA256SUMS.txt)
cat dist/SHA256SUMS.txt
echo "OK dist/NDLoginProbe.dylib dist/BDSLoginProbe.dylib"
