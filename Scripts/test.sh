#!/bin/bash

set -e # stop sript when error occures
set -u # stop when undefined variable is used
#set -x # print all execution (good for debugging)

SCRIPT_FOLDER=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

IOS_VERSION=$(xcrun simctl list | grep "\-\- iOS" | awk -F'-- iOS | --' '{num=$2} END {print num}')
IPHONE_NAME=$(xcrun simctl list | awk '/-- iOS/{pos=NR} /iPhone/ && pos && NR > pos {print; exit}' | awk -F' \\(' '{print $1}'  | awk '{$1=$1; print}')
DESTINATION="platform=iOS Simulator,OS=${IOS_VERSION},name=${IPHONE_NAME}"

echo "Destination Resolved: ${DESTINATION}"

URL=""
APP_NAME=""
URL_TO_PIN=""
LOGIN=""
PASSWORD=""

# Parse parameters of this script
while [[ $# -gt 0 ]]; do
  case "${1}" in
    -url)
      URL="${2}"
      shift
      ;;
    -appname)
      APP_NAME="${2}"
      shift
      ;;
    -urltopin)
      URL_TO_PIN="${2}"
      shift
      ;;
    -login)
      LOGIN="${2}"
      shift
      ;;
    -password)
      PASSWORD="${2}"
      shift
      ;;
    *)
      echo "Unknown parameter ${1}"
      exit 1
      ;;
  esac
  shift
done

if [[ "${URL}" == "" || "${APP_NAME}" == "" || "${URL_TO_PIN}" == "" || "${LOGIN}" == "" || "${PASSWORD}" == "" ]]; then
  echo "Missing parameter(s)."
  exit 1
fi

pushd "${SCRIPT_FOLDER}"
sh cart-update.sh
popd

pushd "${SCRIPT_FOLDER}/.."

echo """{
  \"url\"             : \"${URL}\",
  \"appName\"         : \"${APP_NAME}\",
  \"urlToPin\"        : \"${URL_TO_PIN}\",
  \"adminLogin\"      : \"${LOGIN}\",
  \"adminPassword\"   : \"${PASSWORD}\"
}""" > "Tests/Configs/config.json"

xcrun xcodebuild \
  -derivedDataPath "build" \
  -project "WultraSSLPinning.xcodeproj" \
  -scheme "WultraSSLPinningTests" \
  -configuration "Debug" \
  -destination "${DESTINATION}" \
  -parallel-testing-enabled NO \
  test

popd