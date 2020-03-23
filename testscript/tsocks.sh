#!/usr/bin/env bash
set -eux

HOST="$1"
PORT="$2"

GD="`git rev-parse --show-toplevel`"

cd "$GD"/_test/


FP=`"$GD"/testscript/getfingerprint.sh "$HOST" "$PORT"`

export TSOCKS_USERNAME="$FP"
export TSOCKS_PASSWORD=""
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libtsocks.so TSOCKS_CONF_FILE=tsocks.conf telnet "$HOST" "$PORT"
