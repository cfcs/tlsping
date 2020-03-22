#!/usr/bin/env bash

GD="`git rev-parse --show-toplevel`"

cd $GD/_test/

#Usage: tls_ping_server [OPTION]... CA-PUBLIC-CERT PROXY-PUBLIC-CERT PROXY-SECRET-KEY

$GD/_build/default/tls_ping_server.exe --verbosity debug ca.public.certificate proxy.public.certificate proxy.secret.key


