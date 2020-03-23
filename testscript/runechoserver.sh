#!/usr/bin/env bash
set -eux

GD="`git rev-parse --show-toplevel`"

cd "$GD"/test/
if dune build echo_server.exe
then

cd "$GD"/_test/
"$GD"/_build/default/test/echo_server.exe 4466

else

  echo "build fail"

fi

