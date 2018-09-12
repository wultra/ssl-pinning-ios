#!/bin/sh

# -----------------------------------------------------------------------------
# This helper script re-generates certificate entry for unit testing purposes. 
# The produced JSON file should be added to the following public gist:
#
#   https://gist.github.com/hvge/7c5a3f9ac50332a52aa974d90ea2408c
# -----------------------------------------------------------------------------

set -e
set +v

# -----------------------------------------------------------------------------
PRIVATE_KEY='private.pem'
PINNING_TOOL='ssl-pinning-tool.jar'
DOMAIN='github.com'
OUT='entry.json'
# -----------------------------------------------------------------------------
CERT_FILE=$DOMAIN.pem

if [ ! -f "$PINNING_TOOL" ]; then
	echo "Missing '$PINNING_TOOL'. Please donwload the latest version from:"
	echo "  https://github.com/wultra/ssl-pinning-tool/releases/latest"
	exit 1
fi

openssl s_client -showcerts -connect $DOMAIN:443 -servername $DOMAIN < /dev/null | openssl x509 -outform PEM > $CERT_FILE
java -jar $PINNING_TOOL sign -k $PRIVATE_KEY -c $CERT_FILE -o $OUT

echo "--- printing generated entry ---"
cat $OUT
echo " "
echo "--------------------------------"

# Cleanup
rm $OUT $CERT_FILE
