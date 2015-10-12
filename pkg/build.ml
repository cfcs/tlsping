#!/usr/bin/env ocaml
#directory "pkg";;
#use "topkg.ml";;

let () = Pkg.describe "tlspingd" ~builder:`OCamlbuild [
    Pkg.lib "pkg/META";
    Pkg.bin ~auto:true "tls_ping_client";
    Pkg.bin ~auto:true "tls_ping_server";
    Pkg.doc "readme.md"; ]
