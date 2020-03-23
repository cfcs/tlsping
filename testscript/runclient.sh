#!/usr/bin/env bash
set -eux


GD="`git rev-parse --show-toplevel`"

cd $GD
if dune build 
then
dune build tls_ping_client.exe

cd $GD/_test/

# tls_ping_client: required arguments PROXY-ADDRESS, CA-PUBLIC-CERT, CLIENT-PUBLIC-CERT, CLIENT-SECRET-KEY are missing
#Usage: tls_ping_client [OPTION]... PROXY-ADDRESS CA-PUBLIC-CERT CLIENT-PUBLIC-CERT CLIENT-SECRET-KEY

$GD/_build/default/tls_ping_client.exe --listen 127.0.0.1 --lport 6667 --rport 1312 --verbosity debug \
  localhost ca.public.certificate client.public.certificate client.secret.key
  fi
