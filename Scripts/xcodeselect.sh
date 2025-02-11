#!/bin/bash

set -e

# Script used for selecting proper xcode for all builds on the CI (not appcenter).
# Available xcodes at https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md#xcode

sudo xcode-select -s "/Applications/Xcode_16.2.0.app"