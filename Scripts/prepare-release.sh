#!/bin/bash

set -e # stop script when error occurs
set -u # stop when undefined variable is used
set -o pipefail # stop when error occurs in pipe
#set -x # print all execution (good for debugging)

######### USAGE #########
#
# To prepare or verify release metadata of the library (settings proper version, updating changelog, etc.)
# - this script runs the JavaScript script from Wultra infrastructure repository
# - it uses data defined in `.prepare-release.json` file in the root of the repository
# - it passes all parameters to the JavaScript script
#
#
# It can be run in 3 modes:
#
# 1. With a version (-v X.Y.Z) argument:
#  - it will prepare the release with the current version
#  - use it when you're preparing a new release pull-request
#  - Example: ./Scripts/prepare-release.sh -v 1.0.0
#
# 2. With a version argument and --verify:
#  - it will verify that the given release version is prepared.
#  - use it to make sure that the release pull-request is properly prepared (also used on CI)
#  - Example: ./Scripts/prepare-release.sh -v 1.0.0 --verify
#
# 3. Without arguments:
#  - it will run the script in the root directory of the repository and verify that all files are prepared.
#  - use it to make sure that the current state of the repository is ready for release
#  - Example: ./Scripts/prepare-release.sh
#
# Note: you can add --ignore-git-clean to ignore "git clean" errors (useful when testing things locally)
#
#########################

# path to the script folder
SCRIPT_FOLDER=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# URL of the JavaScript prepare-release script in Wultra infrastructure repository
URL="https://raw.githubusercontent.com/wultra/wultra-infrastructure/refs/heads/mobile-release/mobile-release/v1/prepare-release.js"

# execute the remote node and pass all parameters to it + add path parameter to the root of the repository
curl -fsSL "${URL}" | node - -p "${SCRIPT_FOLDER}/.." "${@}"