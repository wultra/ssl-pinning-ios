#!/bin/bash

set -e # stop script when error occurs
set -u # stop when undefined variable is used
set -o pipefail # stop when error occurs in pipe

###############################################################################
# This script prepares a release with provided version
# ----------------------------------------------------------------------------

TOP=$(dirname $0)
SRC_ROOT="`( cd \"$TOP/..\" && pwd )`"
DO_COMMIT=0
DO_PUSH=0
DO_RELEASE=0
VERSION=
VERSIONING_FILES=(
    "deploy/WultraSSLPinning.podspec,${SRC_ROOT}/WultraSSLPinning.podspec"
)

function USAGE
{
    echo ""
    echo "Usage: prepare-release.sh [options] version"
    echo ""
    echo "options are:"
    echo ""
    echo "  -c | --commit     commit changed files and create tag"
    echo ""
    echo "  -p | --push       push commits and tags"
    echo ""
    echo "  -r | --release    release to CocoaPods"
    echo ""
    echo "  -h | --help       prints this help information"
    echo ""
    exit $1
}

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -c | --commit)
            DO_COMMIT=1
            ;;
        -h | --help)
            USAGE 0
            ;;
        -p | --push)
            DO_PUSH=1
            ;;
        -r | --release)
            DO_RELEASE=1
            ;;
        *)
            VERSION=$opt
            ;;
    esac
    shift
done

if [ -z "${VERSION}" ]; then
    echo "You have to provide version string."
    exit 1
fi

echo "Settings version to ${VERSION}."

pushd $TOP

for (( i=0; i<${#VERSIONING_FILES[@]}; i++ ));
do
    patch_info="${VERSIONING_FILES[$i]}"
    files=(${patch_info//,/ })
    template="${files[0]}"
    target="${files[1]}"
    if [ ! -f "$template" ]; then
        echo "Template file not found: ${template}"
        exit 1
    fi
    if [ ! -f "$target" ]; then
        echo "Target should exist: ${target}"
        exit 1
    fi

    echo "        + ${target}"
    sed -e "s/%DEPLOY_VERSION%/$VERSION/g" "${template}" > "${target}"
    if [ x$DO_COMMIT == x1 ]; then
        git add "${target}"
    fi
done

popd

pushd "${SRC_ROOT}"

if [ x$DO_COMMIT == x1 ]; then
    git commit -m "Bumped version to ${VERSION}"
    git tag "${VERSION}"
fi

if [ x$DO_PUSH == x1 ]; then
    git push --tags
fi

if [ x$DO_RELEASE == x1 ]; then
    pod lib lint
    pod trunk push
fi

popd