#!/usr/bin/env bash
# Генерация корневого CA и сертификата подписанта, выпущенного от корня.
# Результат: certs/root-ca.pem, certs/root-ca-key.pem, certs/signer.pem (issued by root), certs/signer-key.pem.
# SafeBag-сертификаты (driver, passenger, ivi, mobile-driver) не трогаем.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$ROOT/certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

DAYS=365
ECPARAM="-name prime256v1"
EXT_CA="-addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always"
EXT_LEAF="-addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always"

echo "1. Генерация корневого CA..."
openssl ecparam $ECPARAM -genkey -noout -out root-ca-key.pem
openssl req -new -x509 -key root-ca-key.pem -out root-ca.pem -days $((DAYS*2)) \
  -subj "/CN=ATOM Registry Root CA" $EXT_CA

echo "2. Генерация ключа подписанта (Owner Registry Signer)..."
openssl ecparam $ECPARAM -genkey -noout -out signer-key.pem

echo "3. Создание CSR и подпись сертификата корнем..."
openssl req -new -key signer-key.pem -out signer.csr -subj "/CN=Owner Registry Signer"
openssl x509 -req -in signer.csr -CA root-ca.pem -CAkey root-ca-key.pem \
  -CAcreateserial -out signer.pem -days $DAYS -extfile openssl-signer.cnf -extensions v3_signer
rm -f signer.csr root-ca.srl 2>/dev/null || true

echo "Готово. Подписант certs/signer.pem выдан корнем certs/root-ca.pem"
openssl x509 -in signer.pem -noout -subject -issuer
