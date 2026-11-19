#!/bin/sh
# Generate phweb's self-signed test certificate (X.509, RFC 5280 profile,
# issued and consumed by OpenSSL).  For development only — production
# certificate management (ACME / EST) is a recorded gap, see GAP.md.
set -e
mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/phweb.key -out certs/phweb.crt \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:*.test,DNS:*.example,IP:127.0.0.1"
echo "wrote certs/phweb.crt and certs/phweb.key"
