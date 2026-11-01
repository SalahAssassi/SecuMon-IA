#!/usr/bin/env bash
# SecuMon-IA - Génération de la PKI de test (CA + certificats mTLS)
# Données de TEST uniquement. Ne jamais utiliser en production.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKI="$ROOT/pki"
CURVE="prime256v1"   # ECDSA P-256
ORG="/C=MA/O=SecuMon-IA"

mkdir -p "$PKI"/{ca,gateway,terminals,rogue}

echo "==> 1. Autorite de certification racine"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:$CURVE -nodes \
  -keyout "$PKI/ca/ca.key" -out "$PKI/ca/ca.crt" -days 3650 \
  -subj "$ORG/CN=SecuMon-IA Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "==> 2. Certificat serveur de la passerelle"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE -nodes \
  -keyout "$PKI/gateway/gateway.key" -out "$PKI/gateway/gateway.csr" \
  -subj "$ORG/CN=gateway.secumon.local"
openssl x509 -req -in "$PKI/gateway/gateway.csr" \
  -CA "$PKI/ca/ca.crt" -CAkey "$PKI/ca/ca.key" -CAcreateserial \
  -days 365 -out "$PKI/gateway/gateway.crt" \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,DNS:gateway.secumon.local,IP:127.0.0.1")

issue_terminal () {
  local ID="$1"
  echo "==> 3. Certificat client du terminal $ID"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE -nodes \
    -keyout "$PKI/terminals/$ID.key" -out "$PKI/terminals/$ID.csr" \
    -subj "$ORG/OU=Terminals/CN=$ID"
  openssl x509 -req -in "$PKI/terminals/$ID.csr" \
    -CA "$PKI/ca/ca.crt" -CAkey "$PKI/ca/ca.key" -CAcreateserial \
    -days 365 -out "$PKI/terminals/$ID.crt" \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth")
}

issue_terminal "TPE-0001"
issue_terminal "TPE-0002"
issue_terminal "GAB-0001"

echo "==> 4. Fausse CA + terminal pirate (pour les tests d'attaque)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:$CURVE -nodes \
  -keyout "$PKI/rogue/rogue-ca.key" -out "$PKI/rogue/rogue-ca.crt" -days 365 \
  -subj "/C=XX/O=Attacker/CN=Rogue CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:$CURVE -nodes \
  -keyout "$PKI/rogue/TPE-9999.key" -out "$PKI/rogue/TPE-9999.csr" \
  -subj "/C=XX/O=Attacker/CN=TPE-9999"
openssl x509 -req -in "$PKI/rogue/TPE-9999.csr" \
  -CA "$PKI/rogue/rogue-ca.crt" -CAkey "$PKI/rogue/rogue-ca.key" -CAcreateserial \
  -days 365 -out "$PKI/rogue/TPE-9999.crt" \
  -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth")

rm -f "$PKI"/*/*.csr
echo "==> PKI generee dans $PKI"
