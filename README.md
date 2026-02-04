# Утилиты анализа и сборки реестров

Проект содержит три утилиты:

- **registry-analyzer** — разбор контейнеров **ATOM-PKCS12-REGISTRY** (гибрид PKCS#12 PFX и CMS SignedData): сертификаты, подписант, мешки SafeBag (eContent) и ATOM-атрибуты подписантов.
- **registry-builder** — создание реестров .p12 в формате ATOM-PKCS12-REGISTRY по JSON-конфигу.
- **p7-analyzer** — анализ контейнеров **CMS/PKCS#7** (.p7): списки пининга сертификатов без обёртки PFX.

Структура формата ATOM-PKCS12-REGISTRY описана в [registry.asn1](registry.asn1). Workflow и инструкции — в папке [docs/](docs/).

---

## Содержание

- [Требования к окружению](#требования-к-окружению)
- [Точка входа и запуск](#точка-входа-и-запуск)
- [Использование (registry-analyzer)](#использование)
- [p7-analyzer — анализ CMS/PKCS#7 (.p7)](#p7-analyzer--анализ-cmspkcs7-p7)
- [registry-builder — создание реестров](#registry-builder--создание-реестров)
- [Структура проекта](#структура-проекта)
- [Формат контейнера](#формат-контейнера)
- [Проверка через OpenSSL](#проверка-через-openssl)
- [Тесты](#тесты)

Детальный workflow анализа контейнера — в [docs/WORKFLOW.md](docs/WORKFLOW.md). Анализ формата .p7 — в [docs/PKCS7_CMS_ANALYSIS.md](docs/PKCS7_CMS_ANALYSIS.md).

---

## Требования к окружению

- **Go 1.21+** — для сборки и запуска утилит (см. [go.mod](go.mod)).
- **ОС:** Linux, macOS, Windows — используется стандартная библиотека Go (криптография, ASN.1, ввод-вывод). Дополнительные пакеты не требуются.
- **OpenSSL** — опционально, для проверки контейнеров и сертификатов вручную (см. [Проверка через OpenSSL](#проверка-через-openssl) и [docs/OPENSSL_VERIFY.md](docs/OPENSSL_VERIFY.md)).

**Переменные окружения:** утилиты не используют переменные окружения. Цветной вывод в терминале управляется только флагами `-no-color` и `-color` (см. опции каждой утилиты).

---

## Точка входа и запуск

**Точка входа:** `cmd/registry-analyzer/main.go` (пакет `main`, функция `main()`).

**Запуск через `go run`** (из корня репозитория):

```bash
go run ./cmd/registry-analyzer owner_registry.p12
go run ./cmd/registry-analyzer -no-color owner_registry.p12
go run ./cmd/registry-analyzer -format json owner_registry.p12
```

**Сборка бинарников:**

```bash
go build -o registry-analyzer ./cmd/registry-analyzer
go build -o registry-builder ./cmd/registry-builder
go build -o p7-analyzer ./cmd/p7-analyzer
```

### p7-analyzer — анализ CMS/PKCS#7 (.p7)

Утилита для анализа контейнеров **CMS/PKCS#7** (файлы `.p7` без обёртки PFX). Для работы со списками пининга сертификатов (например `pining-list/internal_services_skids_and_certs.p7`).

**Запуск:**

```bash
go run ./cmd/p7-analyzer pining-list/internal_services_skids_and_certs.p7
go run ./cmd/p7-analyzer -format json -output report.json файл.p7
```

**Выгрузка сертификатов (по аналогии с registry-analyzer):**

```bash
# Каждый сертификат из SignedData.certificates в отдельный PEM (cert-N или по подписанту)
./p7-analyzer -export-certs-dir ./certs файл.p7

# Все сертификаты (SignedData + eContent PEM) в один PEM с именем контейнера (file.p7 → file.pem)
./p7-analyzer -export-all-certs файл.p7

# Каждый сертификат из eContent (PEM) в отдельный PEM (econtent-1.pem, econtent-2.pem, …)
./p7-analyzer -export-econtent-certs-dir ./econtent файл.p7

# Сертификат подписанта в файл с суффиксом _signer.pem
./p7-analyzer -export-signer-cert файл.p7
```

**Опции p7-analyzer:**

| Флаг                       | Описание                                                                                                                            | По умолчанию |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `-format`                    | Формат вывода:`text`, `json`, `pem`                                                                                       | `text`                |
| `-output`                    | Записать вывод в указанный файл                                                                                  | stdout                  |
| `-export-certs-dir`          | Каждый сертификат из SignedData.certificates в отдельный PEM (имя: cert-N или по подписанту)  | —                      |
| `-export-all-certs`          | Все сертификаты (SignedData + eContent PEM) в один PEM с именем контейнера                              | выкл                |
| `-export-econtent-certs-dir` | Каждый сертификат из eContent (PEM) в отдельный PEM в указанную директорию (econtent-N.pem) | —                      |
| `-export-signer-cert`        | Сертификат подписанта в PEM (имя контейнера_signer.pem)                                                   | выкл                |
| `-no-color`                  | Отключить цвета и иконки                                                                                               | выкл                |
| `-color`                     | Цвет:`auto`, `always`, `never`                                                                                                    | `auto`                |

Подробный анализ формата CMS — в [docs/PKCS7_CMS_ANALYSIS.md](docs/PKCS7_CMS_ANALYSIS.md).

---

## Использование

```bash
# Текстовый отчёт (по умолчанию)
./registry-analyzer owner_registry.p12

# JSON (полный отчёт)
./registry-analyzer -format json owner_registry.p12

# JSON: данные сертификатов (subject, issuer, serial, сроки, алгоритмы, расширения, SAN, raw DER)
./registry-analyzer -format json-certificates owner_registry.p12

# Запись вывода в файл
./registry-analyzer -format json-certificates -output certs.json owner_registry.p12

# Выгрузка всех сертификатов в PEM для криптоопераций (один файл со всеми сертификатами)
./registry-analyzer -format pem owner_registry.p12
./registry-analyzer -format pem -output certs.pem owner_registry.p12

# Выгрузка каждого сертификата из SignedData в отдельный PEM-файл (имя по roleName подписанта или cert-N.pem)
./registry-analyzer -export-certs-dir ./certs owner_registry.p12

# Выгрузка всех сертификатов из SafeBags в один PEM-файл с именем контейнера (owner_registry.p12 → owner_registry.pem)
./registry-analyzer -export-safebag-certs owner_registry.p12

# Выгрузка каждого сертификата из SafeBags в отдельный PEM-файл (имя: roleName_Serial.pem)
./registry-analyzer -export-safebag-certs-dir ./safebag_certs owner_registry.p12

# Выгрузка только сертификата подписанта контейнера (owner_registry.p12 → owner_registry_signer.pem)
./registry-analyzer -export-signer-cert owner_registry.p12
```

### Опции

| Флаг                      | Описание                                                                                                                                                                                      | По умолчанию |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| `-format`                   | Формат вывода:`text`, `json`, `json-certificates`, `pem`                                                                                                                          | `text`                |
| `-output`                   | Записать вывод в указанный файл                                                                                                                                            | stdout                  |
| `-export-certs-dir`         | Выгрузить каждый сертификат из SignedData в отдельный PEM-файл; имя файла — по атрибуту roleName подписанта (или cert-N.pem) | —                      |
| `-export-safebag-certs`     | Выгрузить все сертификаты из SafeBags в один PEM-файл с именем контейнера (например `owner_registry.pem`)                                | выкл                |
| `-export-safebag-certs-dir` | Выгрузить каждый сертификат из SafeBags в отдельный PEM-файл в указанную директорию (имя: roleName_Serial.pem)                        | —                      |
| `-export-signer-cert`       | Выгрузить только сертификат подписанта контейнера в PEM (например `owner_registry_signer.pem`)                                                | выкл                |
| `-no-color`                 | Отключить цвета и иконки                                                                                                                                                         | выкл                |
| `-color`                    | Цвет:`auto` (только TTY), `always`, `never`                                                                                                                                           | `auto`                |

### Пример вывода (text)

При выводе в TTY используются иконки и ANSI-цвета. Флаг `-no-color` или `-color=never` отключает оформление; в начале вывода выводится ANSI Reset для сброса состояния терминала.

- **PFX** — версия и contentType (pkcs7-signedData).
- **Certificates** — список сертификатов из SignedData (subject, issuer, serial, срок действия, KeyAlg, SubjectKeyId). Сертификат, которым подписан контейнер, помечен как «подписант контейнера».
- **Подписант контейнера** — кто подписал SignedData: Subject, Serial, KeyAlg (сертификат определяется по SubjectKeyIdentifier из SignerInfo).
- **SafeContents (eContent)** — список SafeBag с certId, данными сертификата (subject, issuer, serial, срок, KeyAlg) и атрибутами мешка (roleName, roleValidityPeriod в формате даты-времени, localKeyID и т.д.).
- **Signers and ATOM attributes** — по каждому подписанту: алгоритмы подписи и атрибуты (VIN, VER, UID, roleName, roleValidityPeriod, contentType, messageDigest и т.д.).

### Формат JSON: реальные данные сертификатов

При `-format json` массив `certificates` содержит полные реальные данные каждого сертификата X.509:

| Поле                                                    | Описание                                                                                                              |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `subject`, `issuer`                                     | Субъект и издатель (строка DN).                                                                         |
| `serialNumber`, `serialNumberHex`                       | Серийный номер (десятичная и hex-строка).                                                       |
| `notBefore`, `notAfter`                                 | Срок действия (RFC3339).                                                                                          |
| `version`                                                 | Версия сертификата (1, 2, 3).                                                                                |
| `signatureAlgorithm`, `publicKeyAlgorithm`              | Алгоритмы подписи и публичного ключа.                                                         |
| `subjectKeyId`, `authorityKeyId`                        | Идентификаторы ключей (hex), если есть.                                                           |
| `keyUsage`                                                | Массив имён использования ключа (digitalSignature, keyCertSign и т.д.), если задано. |
| `extKeyUsage`                                             | Массив расширенного использования (serverAuth, clientAuth и т.д.), если задано.   |
| `dnsNames`, `emailAddresses`, `ipAddresses`, `uris` | Subject Alternative Name (SAN), если есть.                                                                            |
| `raw`                                                     | Полный DER сертификата в base64.                                                                            |
| `isSigner`                                                | `true`, если этот сертификат — подписант контейнера.                                  |

При `-format json-certificates` выводится только объект `{"certificates": [...]}` с тем же массивом реальных данных сертификатов (удобно для выгрузки в файл или интеграции с другими инструментами). Опция `-output <файл>` записывает вывод в указанный файл вместо stdout.

### Выгрузка сертификатов в PEM для криптоопераций

Все сертификаты из реестра можно выгрузить в формате PEM для дальнейшего использования в OpenSSL, Go (`crypto/x509`), Java и других библиотеках:

- **`-format pem`** — выводит все сертификаты из SignedData в одном потоке (последовательность блоков `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`). С `-output certs.pem` записывает в файл. В Go: `certPool := x509.NewCertPool(); certPool.AppendPEM(out)` или `x509.ParseCertificates(out)` для списка сертификатов.
- **`-export-certs-dir <директория>`** — создаёт в указанной директории PEM-файлы по одному сертификату из SignedData. Имя файла берётся из атрибута **roleName** подписанта (если есть); при отсутствии roleName или для не-подписантов — `cert-1.pem`, `cert-2.pem`, … При совпадении имён добавляется суффикс `-2`, `-3`. Можно комбинировать с любым `-format`.
- **`-export-safebag-certs`** — выгружает все сертификаты из SafeBags (eContent) в один PEM-файл с именем контейнера: для `owner_registry.p12` создаётся `owner_registry.pem` в той же директории. В файле — только X.509 сертификаты из мешков (Driver, Passenger, IVI и т.д.), готовые для криптоопераций.
- **`-export-safebag-certs-dir <директория>`** — выгружает каждый сертификат из SafeBags в отдельный PEM-файл в указанную директорию. Имя файла формируется из атрибута **roleName** мешка и **Serial** сертификата (hex): `roleName_Serial.pem` (например `delegate_456dbb9c.pem`, `not_delegate_2f29bb9d.pem`). При отсутствии roleName — `cert_Serial.pem` или `cert-N.pem`. При совпадении имён добавляется суффикс `-2`, `-3`.
- **`-export-signer-cert`** — выгружает только сертификат подписанта контейнера (тот, чей SubjectKeyId совпадает с SID в SignerInfo) в файл с суффиксом `_signer.pem`, например `owner_registry_signer.pem`. Удобно для проверки подписи или использования в криптооперациях.

### Как получить сертификат подписанта контейнера

Подписант — сертификат из SignedData, которым подписан контейнер (идентификация по SubjectKeyIdentifier в SignerInfo).

1. **Текстовый отчёт** — в секции «Certificates» нужный сертификат помечен «(подписант контейнера)», в секции «Подписант контейнера» выводятся его Subject, Serial и KeyAlg.
2. **JSON** — при `-format json` или `-format json-certificates` у сертификата подписанта поле `"isSigner": true`. По нему можно выбрать запись и при необходимости декодировать `raw` (base64 DER) в PEM.
3. **PEM-файл** — запуск с флагом **`-export-signer-cert`** создаёт в той же директории файл с именем контейнера и суффиксом `_signer.pem` (например `owner_registry_signer.pem`) с одним сертификатом в PEM. Этот файл можно сразу использовать в OpenSSL или в коде (например, `x509.LoadCertificate` в Go).

---

## registry-builder — создание реестров

Утилита **registry-builder** создаёт реестры на основе структуры данных `registry.asn1`, укажите имя выходного файла реестра. Все созданные реестры проверяются утилитой **registry-analyzer**.

**Подробная инструкция** (формат конфига, подписант, SafeBags, примеры sgw-my-registry и sgw-IVI) — [docs/REGISTRY_BUILDER.md](docs/REGISTRY_BUILDER.md).

**Сборка:**

```bash
go build -o registry-builder ./cmd/registry-builder
```

**Запуск:**

```bash
./registry-builder -config config.json -output sgw-my-registry.p12
```

**Конфигурационный файл (JSON):**

- `signerCert` — путь к PEM сертификата подписанта.
- `signerKey` — путь к PEM приватного ключа подписанта (ECDSA).
- `vin`, `verTimestamp`, `verVersion`, `uid` — атрибуты подписанта (ATOM).
- `safeBags` — массив мешков: для каждого — `cert` (путь к PEM), `roleName`, `roleNotBefore`, `roleNotAfter` (RFC3339), `localKeyID` (hex). Значение `localKeyID` рекомендуется брать из атрибутов предварительно созданных сертификатов (например SubjectKeyIdentifier).

Пример конфига — [docs/registry-builder-config.example.json](docs/registry-builder-config.example.json).

**Проверка созданного реестра:**

```bash
./registry-analyzer sgw-my-registry.p12
./registry-analyzer -format json sgw-my-registry.p12
```

Если разбор проходит без ошибок, структура реестра совместима с эталоном.

---

## Структура проекта

| Путь                          | Назначение                                                                                                                                           |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cmd/registry-analyzer/main.go` | Точка входа registry-analyzer: флаги, run(), чтение .p12, Parse, экспорт и вывод (text/json/json-certificates/pem).          |
| `cmd/registry-builder/main.go`  | Точка входа registry-builder: run(), конфиг (-config, -output sgw-*.p12), BuildRegistry.                                                       |
| `cmd/p7-analyzer/main.go`       | Точка входа p7-analyzer: run(), чтение .p7, ParseCMS/ParseCMSFromPEM, экспорт сертификатов и вывод (text/json/pem).   |
| `internal/registry/`            | Разбор и сборка ATOM-PKCS12-REGISTRY: builder.go, parse.go, asn1_types.go, oid.go, attributes.go, safebag.go, output.go, terminal.go, тесты. |
| `internal/cms/`                 | Разбор CMS/PKCS#7 (.p7): parse.go, types.go, output.go, doc.go. ParseCMS, ParseCMSFromPEM, ToAllPEM, экспорт по cert/econtent.                  |
| `registry.asn1`                 | Спецификация формата ATOM-PKCS12-REGISTRY.                                                                                                  |
| `docs/WORKFLOW.md`              | Workflow анализа контейнера PKCS#12.                                                                                                          |
| `docs/REGISTRY_BUILDER.md`      | Инструкция по registry-builder (конфиг, SafeBags, примеры).                                                                           |
| `docs/PKCS7_CMS_ANALYSIS.md`    | Анализ формата CMS (.p7), опции выгрузки p7-analyzer.                                                                                |
| `docs/OPENSSL_VERIFY.md`        | Проверка контейнера и сертификатов через OpenSSL.                                                                          |
| `docs/CODE_IMPROVEMENTS.md`     | Рекомендации по улучшению кода (Go best practices).                                                                                 |

---

## Формат контейнера

- **Внешняя оболочка:** PFX (PKCS#12), `version = 3`, поле `authSafe` — один **ContentInfo** с `contentType = pkcs7-signedData`.
- **Содержимое content:** CMS **SignedData** (алгоритмы хеширования, encapContentInfo, сертификаты, подписи).
- **eContent (encapContentInfo):** тип `pkcs7-data`, значение — OCTET STRING = **SafeContents** (SEQUENCE OF SafeBag).
- В **SignerInfo.authenticatedAttributes** — кастомные атрибуты ATOM (OID 1.3.6.1.4.1.99999.1.x): VIN, VER, UID, roleName, roleValidityPeriod.

---

## Проверка через OpenSSL

Разбор структуры контейнера:

```bash
openssl asn1parse -in owner_registry.p12 -inform DER
```

Стандартная команда `openssl pkcs12 -info` для такого формата не подходит (ожидается другой тип authSafe). Разбор структуры и **проверка выгруженных сертификатов** (просмотр полей, срок действия, проверка цепочки) — в [docs/OPENSSL_VERIFY.md](docs/OPENSSL_VERIFY.md). Кратко для одного PEM:

```bash
openssl x509 -in owner_registry_signer.pem -noout -subject -issuer -dates -serial
openssl x509 -in owner_registry_signer.pem -noout -text   # полный вывод
openssl verify -CAfile ca.pem owner_registry_signer.pem    # проверка подписи CA
```

---

## Тесты

```bash
go test ./...
```

Тесты используют файл `owner_registry.p12` из корня репозитория (или из текущей директории). В пакете `internal/registry` проверяются разбор PFX, contentType, наличие сертификатов и подписантов, атрибут VIN у первого подписанта и цикл BuildRegistry → Parse.

**Требования:** Go 1.21+. Модуль: `github.com/sgw-registry/registry-analyzer` (см. [go.mod](go.mod)).

---

ATOM CA Team 2025
# atom-a
