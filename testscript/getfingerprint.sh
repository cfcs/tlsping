#!/usr/bin/env bash

set -eux

HOST="$1"
PORT="$2"

echo "sha256 fingerprint of public key: " 1>&2
openssl s_client -showcerts -servername "$HOST" -connect ${HOST}:${PORT} </dev/null 2>/dev/null | openssl x509 -pubkey -noout | grep -v 'PUBLIC KEY' | base64 -d | sha256sum | cut -d ' ' -f 1


