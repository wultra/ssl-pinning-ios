#!/bin/bash

set -e

# Script used for selecting proper xcode for all builds on the CI (not appcenter).
# Available xcodes at https://github.com/actions/runner-images/blob/main/images/macos/macos-26-Readme.md#xcode

REQUIRED_PATH="/Applications/Xcode_26.3.app"
CURRENT_PATH=$( xcode-select -p  | sed -E 's/(\.app).*$/\1/' )

echo "Required xcode: ${REQUIRED_PATH}"
echo "Current xcode:  ${CURRENT_PATH}"

if [[ "${REQUIRED_PATH}" == "${CURRENT_PATH}" ]]; then
  echo "Required and selected xcode are the same."
else
  echo "Selecting ${REQUIRED_PATH}"
  sudo xcode-select -s ${REQUIRED_PATH}
fi