#!/bin/bash

#set -x
set -e

SWIFTLINT_VERSION="0.63.2"
NO_ERROR=false

TOP=$(dirname $0)
PROJECT_HOME="${TOP}/.."
pushd "${PROJECT_HOME}"

while [[ $# -gt 0 ]]
do
    opt="$1"
    case "$opt" in
        -ne | --no-error)
            NO_ERROR=true
            ;;
    esac
    shift
done

function download
{
    DOWNLOAD_FOLDER="swiftlintdownload"
    pushd "${TOP}"
    rm -rf "${DOWNLOAD_FOLDER}"
    mkdir "${DOWNLOAD_FOLDER}"
    pushd "${DOWNLOAD_FOLDER}"
    curl -sSLO "https://github.com/realm/SwiftLint/releases/download/${SWIFTLINT_VERSION}/portable_swiftlint.zip"
    unzip "portable_swiftlint.zip" -d .
    cp "swiftlint" "./../.."
    popd
    rm -rf "${DOWNLOAD_FOLDER}"
    popd
    chmod +x swiftlint
}

echo ""
echo "###################################################"
echo "Running swiftlint to verify code style."

if [ ! -f "swiftlint" ]; then
    echo " > downloading swiftlint ${SWIFTLINT_VERSION}..."
    download
else
    current=$(./swiftlint --version)
    if [ "${SWIFTLINT_VERSION}" != "${current}" ]; then

        echo " > swiftlint ${current} already downloaded, but ${SWIFTLINT_VERSION} is required, removing and downloading."
        rm "swiftlint"
        download

    else
        echo " > Using downloaded swiftlint v${SWIFTLINT_VERSION}."
    fi
fi

EXIT_CODE=0
if [ $NO_ERROR == true ]; then
    PARAM=""
else
    PARAM="--strict"
fi
./swiftlint "${PARAM}" || EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo " > No swiftlint errors 👍."
else
    echo ""
    echo " > ⚠️ There are swiftlint errors."
    if [ $NO_ERROR == true ]; then
        echo " > Build will continue but you need to fix swiftlint issue because otherwise build will fail on the CI."
        EXIT_CODE=0
    else
        echo " > Exiting with error - please fix the swiftlint issues."
        EXIT_CODE=1
    fi
fi
echo "###################################################"
echo ""

exit $EXIT_CODE
