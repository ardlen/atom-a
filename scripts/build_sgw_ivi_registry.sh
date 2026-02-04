#!/usr/bin/env bash
# Создание реестра sgw-IVI_Certificate_registry.p12 с подписантом и содержимым как у IVI_Certificate_registry.p12.
# 1) Экспорт сертификатов из IVI_Certificate_registry.p12 (SafeBags + подписант для справки).
# 2) Генерация нового ключа и сертификата подписанта (CN=IVI-Certificate) — приватный ключ оригинала в .p12 недоступен.
# 3) Сборка sgw-IVI_Certificate_registry.p12 через registry-builder.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IVI_P12="$ROOT/IVI_Certificate_registry.p12"
IVI_CERTS="$ROOT/ivi-certs"
CONFIG="$ROOT/config-ivi.json"
OUTPUT="$ROOT/sgw-IVI_Certificate_registry.p12"

cd "$ROOT"
mkdir -p "$IVI_CERTS"

if [[ ! -f "$IVI_P12" ]]; then
  echo "Файл не найден: $IVI_P12"
  exit 1
fi

echo "Экспорт сертификатов из IVI_Certificate_registry.p12..."
# Важно: флаги перед именем файла (Go flag.Parse останавливается на первом не-флаге).
./registry-analyzer -export-safebag-certs-dir "$IVI_CERTS" "$IVI_P12" 2>/dev/null || true
./registry-analyzer -export-signer-cert "$IVI_P12" 2>/dev/null || true
# signer cert записывается в директорию .p12
if [[ -f "$ROOT/IVI_Certificate_registry_signer.pem" ]]; then
  cp "$ROOT/IVI_Certificate_registry_signer.pem" "$IVI_CERTS/signer-exported.pem"
fi

# Проверяем, что SafeBag-сертификаты есть (имена: roleName_Serial.pem)
SAFEBAG1="$IVI_CERTS/IVI-first-regular_2ec84cc1.pem"
SAFEBAG2="$IVI_CERTS/IVI-second-regular_598f7a8e.pem"
if [[ ! -f "$SAFEBAG1" ]] || [[ ! -f "$SAFEBAG2" ]]; then
  echo "Экспорт SafeBags: ожидаются $SAFEBAG1 и $SAFEBAG2"
  ls -la "$IVI_CERTS" 2>/dev/null || true
  # Пробуем выгрузить по одному через -format pem и разбить, или создаём из JSON
  echo "Запустите: ./registry-analyzer IVI_Certificate_registry.p12 -export-safebag-certs-dir ivi-certs"
  exit 1
fi

echo "Генерация ключа и сертификата подписанта (CN=IVI-Certificate)..."
openssl ecparam -name prime256v1 -genkey -noout -out "$IVI_CERTS/signer-key.pem"
openssl req -new -x509 -key "$IVI_CERTS/signer-key.pem" -out "$IVI_CERTS/signer.pem" -days 365 \
  -subj "/CN=IVI-Certificate" -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always

echo "Сборка реестра: $OUTPUT"
./registry-builder -config "$CONFIG" -output "$OUTPUT"
echo "Готово. Проверка: ./registry-analyzer $OUTPUT"
