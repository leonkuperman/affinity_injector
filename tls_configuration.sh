#! /bin/bash

openssl req -new -nodes -x509 -days 365 \
-keyout tls.key -out tls.crt -config openssl.conf


cat tls.crt | base64 | tr -d '\n' > ca_bundle.txt
