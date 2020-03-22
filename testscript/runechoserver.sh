#!/usr/bin/env bash
set -eux

GD="`git rev-parse --show-toplevel`"

cd "$GD"/_test/
"$GD"/_build/default/test/echo_server.exe 4466


