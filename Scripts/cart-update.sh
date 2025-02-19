#!/bin/bash

set -e # stop sript when error occures

SCRIPT_FOLDER=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

pushd "${SCRIPT_FOLDER}/.."
carthage update --use-xcframeworks --platform ios
popd