# Детальный workflow анализа контейнера PKCS#12 (ATOM-PKCS12-REGISTRY)  с помошью утилит от  Atom CA Team

Документ описывает пошаговый процесс анализа контейнера в формате ATOM-PKCS12-REGISTRY (гибрид PKCS#12 PFX и CMS SignedData): от входного файла до выгрузки сертификатов и проверки через OpenSSL.

---

## Содержание

1. [Входные данные и подготовка](#1-входные-данные-и-подготовка)
2. [Обзор структуры контейнера](#2-обзор-структуры-контейнера)
3. [Структура PKCS#12 и особенности работы с контейнером](#3-структура-pkcs12-и-особенности-работы-с-контейнером)
4. [Workflow утилиты registry-analyzer](#4-workflow-утилиты-registry-analyzer)
5. [Шаг 1: Первичный анализ (текстовый отчёт)](#5-шаг-1-первичный-анализ-текстовый-отчёт)
6. [Шаг 2: Структурированные данные (JSON)](#6-шаг-2-структурированные-данные-json)
7. [Шаг 3: Выгрузка сертификатов](#7-шаг-3-выгрузка-сертификатов)
8. [Шаг 4: Проверка через OpenSSL](#8-шаг-4-проверка-через-openssl)
9. [Шаг 5: Дальнейшее использование](#9-шаг-5-дальнейшее-использование)
10. [Типичные сценарии](#10-типичные-сценарии)
11. [Схема workflow](#11-схема-workflow)

---

## 1. Входные данные и подготовка

### 1.1 Входной объект

- **Файл контейнера** — бинарный DER-файл с расширением `.p12` (например `owner_registry.p12`, `Driver_Certificate_registry.p12`, `IVI_Certificate_registry.p12`).
- **Формат:** PFX (PKCS#12) с `version = 3`, поле `authSafe` — один **ContentInfo** с `contentType = pkcs7-signedData` и телом **SignedData** (CMS). Стандартная команда `openssl pkcs12 -info` для такого контейнера **не подходит** (ожидается другой тип authSafe).

### 1.2 Что нужно иметь

| Инструмент                       | Назначение                                                                                                                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **registry-analyzer**                | Разбор контейнера, отчёты, выгрузка сертификатов в PEM/JSON. Сборка:`go build -o registry-analyzer ./cmd/registry-analyzer` |
| **OpenSSL** (опционально) | Проверка структуры ASN.1, просмотр и верификация выгруженных PEM-сертификатов.                                     |

### 1.3 Сборка утилиты

```bash
cd /path/to/sgw-registry
go build -o registry-analyzer ./cmd/registry-analyzer
```

Или запуск без сборки: `go run ./cmd/registry-analyzer [опции] <файл.p12>`.

---

## 2. Обзор структуры контейнера

Перед анализом полезно представлять, что внутри файла:

```
PFX (version 3)
└── authSafe: ContentInfo
    └── contentType = pkcs7-signedData
    └── content = SignedData
        ├── digestAlgorithms
        ├── encapContentInfo (eContentType = pkcs7-data)
        │   └── eContent = SafeContents (SEQUENCE OF SafeBag)  ← сертификаты реестра (Driver, IVI и т.д.)
        ├── certificates [0]  ← SET OF Certificate (X.509)     ← в т.ч. сертификат подписанта
        └── signerInfos
            └── SignerInfo (sid, digestAlg, signatureAlg, authenticatedAttributes, signature)
                └── authenticatedAttributes: VIN, VER, UID, roleName, roleValidityPeriod, contentType, messageDigest…
```

- **SignedData.certificates** — сертификаты из CMS; среди них сертификат подписанта (идентификация по SubjectKeyIdentifier в SignerInfo).
- **eContent (SafeContents)** — список SafeBag; в каждом мешке CertBag с сертификатом (X.509) и атрибутами мешка (roleName, roleValidityPeriod, localKeyID и т.д.).
- **SignerInfo.authenticatedAttributes** — атрибуты подписи: стандартные (contentType, messageDigest) и кастомные ATOM (VIN, VER, UID, roleName, roleValidityPeriod).

Подробная спецификация — в [registry.asn1](../registry.asn1).

---

## 3. Структура PKCS#12 и особенности работы с контейнером

### 3.1 Стандартный PKCS#12 (PFX)

В классическом PKCS#12 (RFC 7292) контейнер PFX имеет вид:

```
PFX ::= SEQUENCE {
    version    INTEGER {v3(3)},
    authSafe   ContentInfo,        -- здесь ожидается AuthenticatedSafe!
    macData    MacData OPTIONAL
}
```

**AuthenticatedSafe** в стандарте — это **SEQUENCE OF ContentInfo**, где каждый элемент имеет `contentType` либо `data` (1.2.840.113549.1.7.1), либо `encryptedData` (1.2.840.113549.1.7.6). То есть «цепочка» из одного или нескольких блоков Data или EncryptedData. Инструменты вроде OpenSSL и `golang.org/x/crypto/pkcs12` ожидают именно такую структуру в `authSafe`: разбор по одному ContentInfo за раз, извлечение ключей и сертификатов из Data/EncryptedData.

### 3.2 Особенность ATOM-PKCS12-REGISTRY

В формате **ATOM-PKCS12-REGISTRY** внешняя оболочка по-прежнему PFX (version 3), но поле **authSafe** — не AuthenticatedSafe, а **один объект ContentInfo** с:

- **contentType** = `id-signedData` (pkcs7-signedData, OID 1.2.840.113549.1.7.2);
- **content** [0] = **SignedData** (CMS, RFC 5652).

То есть в `authSafe` лежит не SEQUENCE OF ContentInfo, а один ContentInfo, и его тело — не Data/EncryptedData, а **SignedData**. Это гибрид: оболочка PKCS#12, содержимое — CMS SignedData.

Следствия:

| Аспект                  | Стандартный PKCS#12                                                                 | ATOM-PKCS12-REGISTRY                                                                                                                                                        |
| ----------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| authSafe                      | SEQUENCE OF ContentInfo (Data/EncryptedData)                                                   | Один ContentInfo(pkcs7-signedData)                                                                                                                                      |
| Содержимое authSafe | Ключи и сертификаты в мешках (возможно зашифровано) | SignedData: eContent + certificates + signerInfos                                                                                                                           |
| Пароль                  | Часто нужен для MAC/расшифровки                                        | Разбор без пароля (macData опционально не используется)                                                                             |
| `openssl pkcs12 -info`      | Работает                                                                               | **Не работает** — парсер ожидает AuthenticatedSafe, получает один SignedData → ошибки ASN.1 (wrong tag, nested asn1 error) |

Поэтому для анализа таких контейнеров нужна отдельная утилита (registry-analyzer), использующая явный разбор по [registry.asn1](../registry.asn1).

### 3.3 Дерево структур (ASN.1)

Ниже — как устроен контейнер на уровне типов (по registry.asn1).

**Верхний уровень:**

- **PFX**: `version` (3), `authSafe` (ContentInfo), `macData` (опционально).

**ContentInfo (authSafe):**

- `contentType` = OID pkcs7-signedData;
- `content` [0] EXPLICIT = **SignedData**.

**SignedData (CMS):**

- `version`, `digestAlgorithms` (SET OF AlgorithmIdentifier);
- **encapContentInfo** (EncapsulatedContentInfo): `eContentType` = pkcs7-data, `eContent` [0] = OCTET STRING — при декодировании это **SafeContents** (SEQUENCE OF SafeBag);
- **certificates** [0] OPTIONAL — SET OF Certificate (каждый Certificate — OCTET STRING с DER X.509);
- **signerInfos** — SET OF SignerInfo.

**SignerInfo:**

- `version`, **sid** (SignerIdentifier: issuerAndSerialNumber или [0] subjectKeyIdentifier);
- `digestAlgorithm`, **authenticatedAttributes** [0] (SET OF Attribute), `digestEncryptionAlgorithm`, `encryptedDigest`, unauthenticatedAttributes [1].

В **authenticatedAttributes** присутствуют стандартные атрибуты (contentType, messageDigest) и кастомные ATOM (OID 1.3.6.1.4.1.99999.1.x): VIN, VER, UID, roleName, roleValidityPeriod.

**eContent (SafeContents):**

- Декодированный OCTET STRING из encapContentInfo — **SEQUENCE OF SafeBag**.
- **SafeBag**: `bagId` (OID), `bagValue` [0] (CertBag), `bagAttributes` (опционально).
- **CertBag**: `certId` (OID типа сертификата), `certValue` [0] (OCTET STRING — обычно DER X.509).
- В атрибутах мешка могут быть: friendlyName, localKeyID, roleName, roleValidityPeriod (GeneralizedTime) и др.

### 3.4 Два источника сертификатов

При работе с контейнером важно различать:

1. **SignedData.certificates** — набор сертификатов CMS (X.509). Среди них сертификат подписанта контейнера (тот, чей SubjectKeyIdentifier совпадает с sid в SignerInfo). Утилита выводит их в секции «Certificates» и использует для `-format pem`, `-export-certs-dir`, `-export-signer-cert`.
2. **eContent (SafeContents)** — список SafeBag’ов; в каждом CertBag может лежать свой сертификат (например, Driver, Passenger, IVI). Эти сертификаты выводятся в секции «SafeContents (eContent)» и выгружаются флагом `-export-safebag-certs` в один PEM с именем контейнера.

Стандартный PKCS#12 обычно хранит сертификаты в SafeContents внутри Data; здесь SafeContents вложены в **подписанные** данные (eContent SignedData), а отдельно в SignedData лежит набор сертификатов для подписи — отсюда два «слоя» сертификатов.

---

## 4. Workflow утилиты registry-analyzer

Утилита выполняет линейный поток: разбор аргументов → чтение файла → разбор контейнера → при необходимости выгрузка PEM по флагам → вывод в выбранном формате (text/json/json-certificates/pem).

### 4.1 Точка входа (main)

Порядок действий в `cmd/registry-analyzer/main.go`:

1. **Парсинг флагов:** `-format`, `-output`, `-export-certs-dir`, `-export-safebag-certs`, `-export-signer-cert`, `-no-color`, `-color`. Обязательный аргумент — путь к файлу `.p12`.
2. **Чтение файла:** `os.ReadFile(path)` — весь файл в память как `[]byte` (DER).
3. **Разбор контейнера:** `registry.Parse(data)` → возвращает `*Container` или ошибку. При ошибке вывод в stderr и `os.Exit(1)`.
4. **Выгрузка PEM по флагам** (если заданы; порядок фиксирован):

   - **-export-certs-dir** — для каждого сертификата из `c.Certificates` запись в файл `cert-1.pem`, `cert-2.pem`, … в указанную директорию;
   - **-export-safebag-certs** — вызов `c.ToSafeBagsPEM()`, запись в файл `<имя_контейнера>.pem` в той же директории, что и входной файл;
   - **-export-signer-cert** — вызов `c.SignerCertPEM()`, запись в `<имя_контейнера>_signer.pem`; если подписант не найден — ошибка и выход.
5. **Вывод в выбранном формате:**

   - **-format json** → `c.ToJSON()`, вывод (или `-output`) полного отчёта;
   - **-format json-certificates** → `c.ToCertificatesJSON()`, вывод только `{"certificates": [...]}`;
   - **-format pem** → `c.ToPEM()`, вывод PEM всех сертификатов из SignedData;
   - иначе (в т.ч. **text**) → `c.TextOutput(&sb, useColor)`, вывод текстового отчёта (или в файл при `-output`).

Сообщения о записанных файлах (PEM, JSON, текст) выводятся в stderr; основной результат (отчёт или PEM/JSON) — в stdout или в файл из `-output`.

### 4.2 Разбор контейнера (Parse)

В `internal/registry/parse.go` функция **Parse(der []byte)** выполняет:

1. **Unmarshal PFX:** `asn1.Unmarshal(der, &pfx)`. Проверка отсутствия лишних байт после PFX.
2. **Проверка версии:** `pfx.Version == 3`; иначе ошибка.
3. **Проверка authSafe:** `pfx.AuthSafe.ContentType` должен быть равен OID pkcs7-signedData; иначе ошибка.
4. **Unmarshal SignedData:** из `pfx.AuthSafe.Content.Bytes` разбирается структура SignedData (version, digestAlgorithms, encapContentInfo, certificates [0], signerInfos).
5. **Сертификаты SignedData:** если задано `certificates` [0], вызывается **parseCertificateSet**: разбор SET OF Certificate (каждый элемент — OCTET STRING), для каждого OCTET STRING — `x509.ParseCertificate`. Результат — срез `c.Certificates`.
6. **eContent (SafeContents):** если `encapContentInfo.eContentType` = pkcs7-data и `eContent` не пустой, вызывается **parseSafeContents**: разбор SEQUENCE OF SafeBag. Для каждого SafeBag — **ParseSafeBagInfo** (разбор CertBag, при возможности X.509, атрибуты мешка); результат добавляется в `c.SafeBagInfos`. Сырые SafeBag сохраняются в `c.SafeBags`.

Итоговая структура **Container** содержит: PFXVersion, ContentType, SignedData, Certificates, SafeBags, SafeBagInfos, Signers (из SignedData.SignerInfos). Атрибуты подписантов (authenticatedAttributes) разбираются при выводе через **SignerAttributes** / **ParseAuthenticatedAttributes**.

### 4.3 Определение сертификата подписанта

Подписант контейнера — тот, кто подписал SignedData. В SignerInfo он задаётся полем **sid** (SignerIdentifier): в нашем формате используется вариант **[0] subjectKeyIdentifier** (OCTET STRING).

В `internal/registry/terminal.go` функция **SignerCert(si *SignerInfo)** для данного SignerInfo извлекает SubjectKeyIdentifier из `si.SID`, при необходимости разбирает обёртку OCTET STRING, и ищет среди `c.Certificates` сертификат, у которого `cert.SubjectKeyId` совпадает с этим значением. Возвращает найденный `*x509.Certificate` или nil. Этим сертификатом заполняются секция «Подписант контейнера» в текстовом отчёте и флаг `isSigner` в JSON; **SignerCertPEM()** возвращает PEM именно этого сертификата (для первого SignerInfo).

### 4.4 Формирование вывода

- **Текстовый отчёт:** `output.TextOutput` выводит по очереди секции PFX, Certificates (с пометкой подписанта), Подписант контейнера, SafeContents (eContent), Signers and ATOM attributes. Цвета и иконки задаются пакетом `terminal` и флагом `-no-color`/`-color`.
- **JSON:** `JSONOutput()` собирает карту с ключами pfxVersion, contentType, certificates (полные данные через certToJSONMap), safeBags (bagId, certId, certSummary, bagAttributes), signers (алгоритмы и расшифрованные атрибуты). **CertificatesJSONOutput()** возвращает только `{"certificates": [...]}`.
- **PEM:** `ToPEM()` — конкатенация PEM-блоков всех `c.Certificates`. `ToSafeBagsPEM()` — конкатенация PEM из `CertValueDER` всех SafeBagInfos. `SignerCertPEM()` — PEM одного сертификата, возвращаемого `SignerCert` для первого подписанта.

Таким образом, workflow утилиты: один проход разбора (Parse) → заполнение Container → затем только чтение из Container при выгрузке PEM и формировании отчёта/JSON.

---

## 5. Шаг 1: Первичный анализ (текстовый отчёт)

Цель: быстро увидеть содержимое контейнера в человекочитаемом виде.

### 5.1 Запуск

```bash
./registry-analyzer owner_registry.p12
```

При выводе в TTY используются цвета и иконки. Для отключения: `-no-color` или `-color=never`.

### 5.2 На что смотреть в отчёте

| Секция                                      | Содержимое                                                                                                                                                                                                                     |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **PFX**                                     | Версия (3), contentType (pkcs7-signedData).                                                                                                                                                                                        |
| **Certificates**                            | Список сертификатов из SignedData: Subject, Issuer, Serial, срок действия, KeyAlg, SubjectKeyId. Сертификат подписанта помечен «(подписант контейнера)». |
| **Подписант контейнера** | Кто подписал SignedData: Subject, Serial, KeyAlg (по SID из SignerInfo).                                                                                                                                                  |
| **SafeContents (eContent)**                 | Список SafeBag: bagId, certId, данные сертификата (Subject, Issuer, Serial, срок, KeyAlg), атрибуты мешка (roleName, roleValidityPeriod в формате даты-времени, localKeyID).  |
| **Signers and ATOM attributes**             | По каждому подписанту: DigestAlgorithm, SignatureAlgorithm, атрибуты (VIN, VER, UID, roleName, roleValidityPeriod, contentType, messageDigest и т.д.).                                                     |

### 5.3 Сохранение отчёта в файл

```bash
./registry-analyzer -output report.txt owner_registry.p12
```

---

## 6. Шаг 2: Структурированные данные (JSON)

Цель: получить машиночитаемый вывод для скриптов, интеграции или хранения.

### 6.1 Полный отчёт (PFX + сертификаты + SafeBags + подписанты)

```bash
./registry-analyzer -format json owner_registry.p12
./registry-analyzer -format json -output report.json owner_registry.p12
```

Структура: `pfxVersion`, `contentType`, `certificates` (полные данные каждого сертификата), `safeBags` (bagId, certId, certSummary, bagAttributes), `signers` (алгоритмы и атрибуты).

### 6.2 Только данные сертификатов (SignedData)

```bash
./registry-analyzer -format json-certificates owner_registry.p12
./registry-analyzer -format json-certificates -output certs.json owner_registry.p12
```

Вывод: объект `{"certificates": [...]}`. В каждом элементе: `subject`, `issuer`, `serialNumber`, `serialNumberHex`, `notBefore`, `notAfter`, `version`, `signatureAlgorithm`, `publicKeyAlgorithm`, `subjectKeyId`, `authorityKeyId`, `keyUsage`, `extKeyUsage`, SAN, `raw` (base64 DER), `isSigner`.

---

## 7. Шаг 3: Выгрузка сертификатов

Цель: получить PEM-файлы для использования в OpenSSL, приложениях (Go, Java и т.д.) и криптооперациях.

### 7.1 Сертификаты из SignedData (в т.ч. подписант)

| Задача                                                                      | Команда                                                                                                                   | Результат                                                                                 |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Все сертификаты SignedData в один PEM (stdout или файл) | `./registry-analyzer -format pem owner_registry.p12<br>``./registry-analyzer -format pem -output certs.pem owner_registry.p12` | Один файл с последовательностью PEM-блоков.                      |
| Каждый сертификат SignedData в отдельный файл       | `./registry-analyzer -export-certs-dir ./certs owner_registry.p12`                                                             | В `./certs`: `cert-1.pem`, `cert-2.pem`, …                                                 |
| Только сертификат подписанта контейнера       | `./registry-analyzer -export-signer-cert owner_registry.p12`                                                                   | В той же директории:`owner_registry_signer.pem` (один сертификат). |

### 7.2 Сертификаты из SafeBags (eContent)

| Задача                                                | Команда                                                   | Результат                                                                                   |
| ----------------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Все сертификаты из SafeBags в один PEM | `./registry-analyzer -export-safebag-certs owner_registry.p12` | В той же директории:`owner_registry.pem` (имя контейнера + `.pem`). |

### 7.3 Комбинирование флагов

Можно одновременно выгружать и отчёт, и сертификаты:

```bash
./registry-analyzer -export-signer-cert -export-safebag-certs -format json -output report.json owner_registry.p12
```

В результате: `owner_registry_signer.pem`, `owner_registry.pem`, `report.json` и текстовый отчёт в stdout.

---

## 8. Шаг 4: Проверка через OpenSSL

Цель: проверить выгруженные PEM-сертификаты и (при необходимости) сырую структуру контейнера.

### 8.1 Просмотр одного PEM-сертификата

```bash
openssl x509 -in owner_registry_signer.pem -noout -subject -issuer -dates -serial
openssl x509 -in owner_registry_signer.pem -noout -text
```

### 8.2 Проверка срока действия

```bash
openssl x509 -in owner_registry_signer.pem -noout -dates
openssl x509 -in owner_registry_signer.pem -noout -checkend 0 && echo "действителен" || echo "истёк"
```

### 8.3 Проверка цепочки доверия (если есть CA)

```bash
openssl verify -CAfile ca.pem owner_registry_signer.pem
```

### 8.4 Разбор структуры контейнера (ASN.1)

```bash
openssl asn1parse -in owner_registry.p12 -inform DER
openssl asn1parse -in owner_registry.p12 -inform DER -out asn1_dump.txt
```

Подробный перечень команд OpenSSL — в [docs/OPENSSL_VERIFY.md](OPENSSL_VERIFY.md).

---

## 9. Шаг 5: Дальнейшее использование

- **Криптооперации:** загрузка PEM в приложение (например, в Go: `x509.LoadCertificate`, `x509.NewCertPool().AppendPEM()`; проверка подписи, TLS и т.д.).
- **Интеграция:** потребление JSON (`report.json`, `certs.json`) скриптами или системами мониторинга.
- **Аудит:** хранение отчётов и выгруженных сертификатов для соответствия и расследований.

---

## 10. Типичные сценарии

### Сценарий A: «Быстро посмотреть, что в контейнере»

```bash
./registry-analyzer owner_registry.p12
```

### Сценарий B: «Нужен только сертификат подписанта для проверки подписи»

```bash
./registry-analyzer -export-signer-cert owner_registry.p12
openssl x509 -in owner_registry_signer.pem -noout -subject -dates
# далее использовать owner_registry_signer.pem в приложении
```

### Сценарий C: «Выгрузить все сертификаты реестра (SafeBags) в один PEM»

```bash
./registry-analyzer -export-safebag-certs owner_registry.p12
# owner_registry.pem — все сертификаты из мешков (Driver, Passenger, IVI и т.д.)
```

### Сценарий D: «Полный отчёт в JSON + все PEM для криптоопераций»

```bash
./registry-analyzer -format json -output report.json \
  -export-signer-cert -export-safebag-certs \
  -export-certs-dir ./signeddata_certs \
  owner_registry.p12
```

В результате: `report.json`, `owner_registry_signer.pem`, `owner_registry.pem`, в `./signeddata_certs` — `cert-1.pem`, …

### Сценарий E: «Проверить структуру контейнера через OpenSSL перед анализом»

```bash
openssl asn1parse -in owner_registry.p12 -inform DER | head -80
./registry-analyzer owner_registry.p12
```

---

## 11. Схема workflow

```
                    ┌─────────────────────┐
                    │  Контейнер .p12     │
                    │  (DER, PFX v3)      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ registry-analyzer   │
                    │ Parse(der)          │
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌─────────────────┐  ┌────────────────-─┐  ┌────────────-─────┐
│ -format text    │  │ -format json     │  │ -format pem      │
│ (по умолчанию)  │  │ -format          │  │ -export-signer-  │
│                 │  │ json-certificates│  │ cert             │
│ Текстовый отчёт │  │ JSON в файл/     │  │ -export-safebag- │
│ (PFX, Certs,    │  │ stdout           │  │ certs            │
│  SafeBags,      │  │                  │  │ -export-certs-dir│
│  Signers)       │  │                  │  │ PEM-файлы        │
└────────┬────────┘  └────────┬───────-─┘  └────────┬──-──────┘
         │                     │                    │
         │                     │                    ▼
         │                     │            ┌─────────────────┐
         │                     │            │ OpenSSL         │
         │                     │            │ x509, verify,   │
         │                     │            │ asn1parse       │
         │                     │            └─────────────────┘
         ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Результат: отчёты, JSON, PEM-сертификаты для аудита,       │
│  криптоопераций и проверки цепочки доверия                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Связанные документы

| Документ                             | Описание                                                                                         |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| [README.md](../README.md)                       | Обзор утилиты, опции, примеры.                                                   |
| [registry.asn1](../registry.asn1)               | Спецификация формата ATOM-PKCS12-REGISTRY.                                            |
| [docs/OPENSSL_VERIFY.md](OPENSSL_VERIFY.md)     | Проверка структуры контейнера и сертификатов через OpenSSL. |
| [docs/DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) | План разработки и этапы реализации.                                        |

---

**ATOM CA Team 2025**
