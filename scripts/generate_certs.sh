#!/usr/bin/env bash
# Генерация набора сертификатов для сборки реестра, аналогичного owner_registry.p12:
# - подписант контейнера (Owner Registry Signer) + ключ;
# - четыре сертификата для SafeBags: Driver, Passenger, IVI, Mobile-Driver.
# После запуска создаётся certs/ и config.json с актуальными localKeyID (SubjectKeyIdentifier).

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$ROOT/certs"
CONFIG_JSON="$ROOT/config.json"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

# Параметры ECDSA P-256 и срок действия (1 год)
DAYS=365
ECPARAM="-name prime256v1"
EXT_SKI="-addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always"

echo "Генерация ключа и сертификата подписанта (Owner Registry Signer)..."
openssl ecparam $ECPARAM -genkey -noout -out signer-key.pem
openssl req -new -x509 -key signer-key.pem -out signer.pem -days $DAYS \
  -subj "/CN=Owner Registry Signer" $EXT_SKI

echo "Генерация сертификатов для SafeBags..."
gen_safebag_cert() {
  local subj="$1"
  local certfile="$2"
  openssl ecparam $ECPARAM -genkey -noout -out "${certfile%.pem}-key.pem"
  openssl req -new -x509 -key "${certfile%.pem}-key.pem" -out "$certfile" -days $DAYS \
    -subj "/$subj" $EXT_SKI
}
gen_safebag_cert "CN=Driver-Certificate" driver.pem
gen_safebag_cert "CN=Passenger-Certificate" passenger.pem
gen_safebag_cert "CN=IVI-Certificate" ivi.pem
gen_safebag_cert "CN=Mobile-Driver-Certificate" mobile-driver.pem

# Извлечь SubjectKeyIdentifier (hex без двоеточий) для каждого SafeBag-сертификата
get_ski_hex() {
  openssl x509 -in "$1" -noout -ext subjectKeyIdentifier 2>/dev/null | \
    sed 's/.*=//;s/://g' | tr 'A-F' 'a-f'
}

echo "Извлечение SubjectKeyIdentifier для config.json..."
SKI_DRIVER=$(get_ski_hex driver.pem)
SKI_PASSENGER=$(get_ski_hex passenger.pem)
SKI_IVI=$(get_ski_hex ivi.pem)
SKI_MOBILE=$(get_ski_hex mobile-driver.pem)

# Записать config.json с актуальными localKeyID
cat > "$CONFIG_JSON" << EOF
{
  "signerCert": "certs/signer.pem",
  "signerKey": "certs/signer-key.pem",
  "vin": "EAY2AT0MPS2013376",
  "verTimestamp": "2024-01-01T00:00:00Z",
  "verVersion": 100,
  "uid": "emailAddress=client.a@atom.team,CN=Client A,OU=Sales,O=KAMA,L=SPb,ST=SPb,C=RU",
  "safeBags": [
    {
      "cert": "certs/driver.pem",
      "roleName": "delegate",
      "roleNotBefore": "2026-01-15T17:40:20Z",
      "roleNotAfter": "2027-01-15T17:40:20Z",
      "localKeyID": "$SKI_DRIVER"
    },
    {
      "cert": "certs/passenger.pem",
      "roleName": "not_delegate",
      "roleNotBefore": "2026-01-15T17:40:20Z",
      "roleNotAfter": "2027-01-15T17:40:20Z",
      "localKeyID": "$SKI_PASSENGER"
    },
    {
      "cert": "certs/ivi.pem",
      "roleName": "delegate",
      "roleNotBefore": "2026-01-15T17:40:21Z",
      "roleNotAfter": "2027-01-15T17:40:21Z",
      "localKeyID": "$SKI_IVI"
    },
    {
      "cert": "certs/mobile-driver.pem",
      "roleName": "driver-mobile",
      "roleNotBefore": "2026-01-15T17:40:21Z",
      "roleNotAfter": "2027-01-15T17:40:21Z",
      "localKeyID": "$SKI_MOBILE"
    }
  ]
}
EOF

echo "Готово."
echo "  Сертификаты: $CERTS_DIR/"
echo "  Конфиг:      $CONFIG_JSON"
echo ""
echo "Сборка реестра:"
echo "  cd $ROOT && ./registry-builder -config config.json -output sgw-my-registry.p12"
echo "Проверка:"
echo "  ./registry-analyzer sgw-my-registry.p12"
