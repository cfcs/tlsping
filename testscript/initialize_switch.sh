#!/usr/bin/env bash
set -eux

if opam switch create tlsping 4.09.0
then
  echo "switch already exist, switching"
  opam switch tlsping
fi

opam pin add -n socks --dev -k git 'https://github.com/cfcs/ocaml-socks#master'
opam pin add -n socks-lwt --dev -k git 'https://github.com/cfcs/ocaml-socks#master'
opam pin add -n tls.0.11.0 --dev -k git 'https://github.com/cfcs/ocaml-tls#expose_engine_state'
opam install alcotest cmdliner fmt hex logs lwt rresult x509 tls socks socks-lwt ocp-indent certify.0.3.2 tls.lwt


