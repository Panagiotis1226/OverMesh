#!/usr/bin/env bash
# Builds Mobilecore.xcframework (device + simulator) from
# mobilecore via gomobile. Run on macOS with Xcode installed.
#
#   clients/ios/build-ios.sh
#
# Then: xcodegen generate (in clients/ios) and open OverMesh.xcodeproj.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

command -v go >/dev/null || { echo "need Go 1.26+ (https://go.dev/dl)"; exit 1; }
command -v xcodebuild >/dev/null || { echo "need Xcode command line tools"; exit 1; }

# gomobile + gobind pinned to the x/mobile version in go.mod, so a
# fresh checkout always builds with the same generator.
XMOBILE=$(go list -m -f '{{.Version}}' golang.org/x/mobile)
echo "==> installing gomobile/gobind $XMOBILE"
GOBIN="$PWD/bin" go install "golang.org/x/mobile/cmd/gomobile@$XMOBILE" \
  "golang.org/x/mobile/cmd/gobind@$XMOBILE"
export PATH="$PWD/bin:$PATH"

echo "==> gomobile bind (ios, iossimulator)"
gomobile bind -target ios,iossimulator -iosversion 16.0 \
  -o clients/ios/Mobilecore.xcframework ./mobilecore

echo "==> done: clients/ios/Mobilecore.xcframework"
echo "next: cd clients/ios && xcodegen generate && open OverMesh.xcodeproj"
