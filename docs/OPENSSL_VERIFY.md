# Проверка структуры и сертификатов через OpenSSL

## Проверка сертификатов (PEM после выгрузки утилитой)

После выгрузки сертификатов утилитой (`-export-signer-cert`, `-export-safebag-certs`, `-format pem -output …`) проверять их можно так.

### Просмотр одного сертификата (PEM)

```bash
# Кратко: субъект, издатель, срок действия, серийный номер
openssl x509 -in owner_registry_signer.pem -noout -subject -issuer -dates -serial

# Полная информация (все поля и расширения)
openssl x509 -in owner_registry_signer.pem -noout -text

# Только расширения
openssl x509 -in owner_registry_signer.pem -noout -ext keyUsage,extendedKeyUsage,subjectKeyIdentifier,authorityKeyIdentifier
```

### Файл с несколькими сертификатами (например owner_registry.pem из SafeBags)

```bash
# Просмотр всех сертификатов по очереди (каждый блок -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)
openssl storeutl -noout -text -certs owner_registry.pem

# Или вручную: только субъекты (первая строка каждого блока после subject=)
openssl crl2pkcs7 -nocrl -certfile owner_registry.pem | openssl pkcs7 -print_certs -noout -text | grep "subject="
```

По одному сертификату из многоблочного PEM:

```bash
# Извлечь первый сертификат во временный файл и проверить
openssl x509 -in owner_registry.pem -noout -subject -dates

# Второй, третий и т.д. (нужен номер блока; можно разбить через csplit или скрипт)
csplit -s -f cert- owner_registry.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
openssl x509 -in cert-01 -noout -subject -dates
```

### Проверка срока действия

```bash
# Только даты (notBefore, notAfter)
openssl x509 -in owner_registry_signer.pem -noout -dates

# Проверить, не истёк ли сертификат (код выхода 0 = действителен)
openssl x509 -in owner_registry_signer.pem -noout -checkend 0 && echo "действителен" || echo "истёк или ещё не действует"
```

### Проверка подписи сертификата (цепочка доверия)

Если есть сертификат издателя (CA) в PEM:

```bash
# Проверить, что сертификат подписан указанным CA (ca.pem — сертификат CA или цепочка)
openssl verify -CAfile ca.pem owner_registry_signer.pem

# Несколько сертификатов в одном файле CA (например цепочка)
openssl verify -CAfile chain.pem owner_registry_signer.pem
```

Если CA нет в файле, а сертификат самоподписанный (issuer = subject), `openssl verify` без `-CAfile` выдаст ошибку — для самоподписанных достаточно проверки дат и полей через `x509 -text`.

---

## Проверка цепочки доверия на основе тестовых сертификатов (root-ca.pem)

В тестовом стенде подписант реестра может быть выпущен **от корневого CA**. Корень и подписант создаются скриптом [scripts/generate_signer_from_root.sh](../scripts/generate_signer_from_root.sh). Для полной проверки цепочки нужны **два файла**:

| Файл | Описание |
|------|----------|
| **certs/root-ca.pem** | Сертификат корневого CA (CN=ATOM Registry Root CA). Доверенный корень для проверки. |
| **\<имя_реестра\>_signer.pem** | Сертификат подписанта контейнера (CN=Owner Registry Signer), выгруженный из реестра. |

### Шаг 1: Выгрузить сертификат подписанта из реестра

Сертификат подписанта лежит внутри .p12 в SignedData.certificates; для проверки цепочки его нужно экспортировать в PEM:

```bash
./registry-analyzer -export-signer-cert sgw-owner-6-new.p12
```

Создаётся файл **sgw-owner-6-new_signer.pem** (имя формируется как `<имя_контейнера>_signer.pem`).

### Шаг 2: Проверить цепочку доверия

Подписант должен быть выдан корнем. Команда:

```bash
openssl verify -CAfile certs/root-ca.pem sgw-owner-6-new_signer.pem
```

Ожидаемый вывод при успехе:

```text
sgw-owner-6-new_signer.pem: OK
```

Это означает: сертификат подписанта действителен и подписан доверенным корнем **certs/root-ca.pem**.

### Шаг 3: Просмотр цепочки (опционально)

```bash
# Подписант: кто выдал и срок действия
openssl x509 -in sgw-owner-6-new_signer.pem -noout -subject -issuer -dates

# Корень (самоподписанный)
openssl x509 -in certs/root-ca.pem -noout -subject -issuer -dates
```

Типичный вывод для подписанта: `subject= CN=Owner Registry Signer`, `issuer= CN=ATOM Registry Root CA`.

### Как получить тестовые сертификаты (root + подписант)

Скрипт создаёт корневой CA и подписанта, выпущенного от корня:

```bash
./scripts/generate_signer_from_root.sh
```

В каталоге **certs/** появятся:

- **root-ca.pem**, **root-ca-key.pem** — корневой CA (храните root-ca-key.pem в безопасном месте или только для тестов).
- **signer.pem**, **signer-key.pem** — подписант (signer.pem выпущен от root-ca.pem).

После этого сборка реестра (`./registry-builder -config config.json -output sgw-owner-6-new.p12`) подписывает контейнер этим подписантом; цепочку затем проверяют по шагам 1–2 выше.

**Итог:** для полной проверки цепочки подписи реестра нужны **root-ca.pem** (доверенный корень) и **\<реестр\>_signer.pem** (сертификат подписанта, экспортированный из .p12).

### Ошибка 18: self signed certificate

При проверке подписанта контейнера (`owner_registry_signer.pem`) часто возникает:

```text
openssl verify -CAfile Driver_Certificate_registry.pem owner_registry_signer.pem
error 18 at 0 depth lookup:self signed certificate
owner_registry_signer.pem: verification failed: 18 (self signed certificate)
```

**Почему так:** сертификат подписанта (Owner Registry Signer) **самоподписан**: issuer = subject. Файл `-CAfile` (например `Driver_Certificate_registry.pem`) содержит сертификаты из **SafeBags** (Driver, IVI и т.д.), а не издателя подписанта. OpenSSL не находит в цепочке CA, выпустивший этот сертификат, и помечает его как self signed → код 18.

**Что делать:**

1. **Проверить самоподписанный сертификат «сам по себе»** — использовать его же как доверенный корень (проверка целостности и срока):

   ```bash
   openssl verify -CAfile owner_registry_signer.pem owner_registry_signer.pem
   ```

   Успех означает, что сертификат непротиворечив и действителен на текущую дату.
2. **Только проверить срок и поля** (без цепочки доверия):

   ```bash
   openssl x509 -in owner_registry_signer.pem -noout -subject -issuer -dates
   openssl x509 -in owner_registry_signer.pem -noout -checkend 0 && echo "действителен"
   ```

   Для самоподписанного сертификата issuer и subject совпадают.
3. **Не использовать как CA файл с другими сертификатами** — `Driver_Certificate_registry.pem` и подобные содержат сертификаты реестра (SafeBags), они не являются издателем подписанта контейнера.

### Публичный ключ и алгоритм

```bash
openssl x509 -in owner_registry_signer.pem -noout -pubkey -text | head -20
```

### Конвертация PEM ↔ DER

```bash
# PEM → DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER → PEM
openssl x509 -in cert.der -inform DER -out cert.pem
```

---

## Разбор ASN.1 структуры контейнера (рекомендуется)

```bash
# Полный вывод дерева структуры
openssl asn1parse -in owner_registry.p12 -inform DER

# С сохранением в файл для анализа
openssl asn1parse -in owner_registry.p12 -inform DER -out asn1_dump.txt
```

Ожидаемая структура:

- `d=0` SEQUENCE (PFX)
  - INTEGER :03 (version)
  - SEQUENCE (ContentInfo)
    - OBJECT :pkcs7-signedData
    - cont [ 0 ] → SignedData
      - digestAlgorithms (SET, sha256)
      - encapContentInfo (pkcs7-data, OCTET STRING = SafeContents)
      - cont [ 0 ] → certificates (SET of certs)
      - SET → signerInfos (authenticatedAttributes с OID 1.3.6.1.4.1.99999.1.1–1.3.6.1.4.1.99999.1.5)

## Поиск ATOM-атрибутов в дампе

```bash
openssl asn1parse -in owner_registry.p12 -inform DER | grep -E "99999|UTF8STRING|GENERALIZEDTIME"
```

## Проверка сертификата (после извлечения в DER)

```bash
openssl x509 -in cert.der -inform DER -noout -text -subject -issuer -dates -serial
```

## Почему pkcs12 -info не подходит

Стандартная команда ожидает в authSafe структуру AuthenticatedSafe (SEQUENCE OF ContentInfo с Data или EncryptedData). В нашем формате в authSafe лежит один ContentInfo с **SignedData**. Поэтому:

```bash
openssl pkcs12 -in owner_registry.p12 -info -noout
# → ошибки ASN.1 (wrong tag, nested asn1 error)
```

Для разбора таких контейнеров нужна  утилита `registry-analyzer`

---

**ATOM CA Team 2025**
