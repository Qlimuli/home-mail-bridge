#!/bin/bash
# Erzeugt ein Self-Signed Zertifikat für Dovecot (für den internen Gebrauch ausreichend)
set -e

SSL_DIR="${1:-./data/dovecot-ssl}"
mkdir -p "$SSL_DIR"

if [ -f "$SSL_DIR/dovecot.pem" ] && [ -f "$SSL_DIR/dovecot.key" ]; then
  echo "Zertifikat existiert bereits – überspringe"
  exit 0
fi

echo "Erzeuge Self-Signed Zertifikat in $SSL_DIR …"
openssl req -new -x509 -days 3650 -nodes \
  -out "$SSL_DIR/dovecot.pem" \
  -keyout "$SSL_DIR/dovecot.key" \
  -subj "/CN=home-mail-bridge/O=HomeMail/C=DE"

chmod 644 "$SSL_DIR/dovecot.pem"
chmod 600 "$SSL_DIR/dovecot.key"
echo "Fertig."
