#!/usr/bin/env bash
set -e
cd "`git rev-parse --show-toplevel`"
mkdir -p _test
cd _test

certify selfsign --ca -k ca.secret.key -c ca.public.certificate my.friends.example.org
certify csr --out client.csr -k client.secret.key client.example.org "A friend of ours"
certify sign --client --cain ca.public.certificate --key ca.secret.key --csrin client.csr --out client.public.certificate
certify csr --out proxy.csr -k proxy.secret.key proxy.example.org "One of our proxies"
certify sign --cain ca.public.certificate --key ca.secret.key --csrin proxy.csr --out proxy.public.certificate


