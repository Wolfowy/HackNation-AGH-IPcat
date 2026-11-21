#!/usr/bin/env sh
# Development PKI: a local CA plus a server certificate for the WebScan server container.
# Agents pin ca.crt (Server__CaCertificatePath). Output: ca.crt, ca.key, server.crt, server.key in this directory.
# Usage: deploy/docker/certs/generate-certs.sh [--force]
set -eu

cd "$(dirname "$0")"

if [ -f server.crt ] && [ "${1:-}" != "--force" ]; then
  echo "Certificates already exist (use --force to regenerate)."
  exit 0
fi

DAYS=825

openssl req -x509 -new -nodes -newkey rsa:3072 -sha256 -days 3650 \
  -keyout ca.key -out ca.crt \
  -subj "/CN=WebScan Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -nodes -newkey rsa:2048 -sha256 \
  -keyout server.key -out server.csr \
  -subj "/CN=server"

cat > server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" -sha256 -extfile server.ext

rm -f server.csr server.ext ca.srl
# The server runs as a non-root user inside the container and must be able to read the key from the bind mount.
chmod 644 server.key server.crt ca.crt
chmod 600 ca.key

echo "Generated ca.crt, server.crt (SAN: server, localhost, 127.0.0.1) and keys in $(pwd)"
