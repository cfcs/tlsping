#!/usr/bin/env bash

HOST="$1"
PORT="$2"

echo "sha256 fingerprint of public key: "
openssl s_client -showcerts -servername "$HOST" -connect ${HOST}:${PORT} 2>/dev/null | openssl x509 -pubkey -noout | grep -v 'PUBLIC KEY' | base64 -d | sha256sum


