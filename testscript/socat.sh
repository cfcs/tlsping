#!/usr/bin/env bash
set -eux

HOST="$1"
PORT="$2"

GD="`git rev-parse --show-toplevel`"

cd "$GD"/_test/


FP=`"$GD"/testscript/getfingerprint.sh "$HOST" "$PORT"`

socat stdio socks4a:localhost:"$HOST":"$PORT",socksport=6667,socksuser="$FP"
