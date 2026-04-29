#!/bin/bash

set -e # stop script when error occurs

SCRIPT_FOLDER=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

pushd "${SCRIPT_FOLDER}/.."
carthage update --use-xcframeworks --platform ios
popd