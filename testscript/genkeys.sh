#!/usr/bin/env bash
set -eux
cd "`git rev-parse --show-toplevel`"
mkdir -p _test
cd _test

certify selfsign --ca -k ca.secret.key -c ca.public.certificate my.friends.example.org

# client running on your laptop
certify csr --out client.csr -k client.secret.key client.example.org "A friend of ours"
certify sign --client --cain ca.public.certificate --key ca.secret.key --csrin client.csr --out client.public.certificate

# proxy running on untrusted server
certify csr --out proxy.csr -k proxy.secret.key proxy.example.org "the tls-ping proxy"
certify sign --cain ca.public.certificate --key ca.secret.key --csrin proxy.csr --out proxy.public.certificate

# irc server
certify csr --out irc_server.csr -k irc_server.secret.key localhost "irc server"
certify sign --cain ca.public.certificate --key ca.secret.key --csrin irc_server.csr --out irc_server.public.certificate


