#!/bin/bash

set -e # stop sript when error occures
set -u # stop when undefined variable is used
#set -x # print all execution (good for debugging)

SCRIPT_FOLDER=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

pushd "${SCRIPT_FOLDER}/.."

xcrun xcodebuild \
  -project "WultraSSLPinning.xcodeproj" \
  -scheme "WultraSSLPinning" \
  -configuration "Release" \
  -sdk "iphonesimulator" \
  build

popd