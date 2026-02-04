# Анализ контейнера PKCS#7 / CMS  pinning-list

Документ содержит инструкцию анализа pinnig list 

---

**Обзор**

Файл `pining-list/internal_services_skids_and_certs.p7` — контейнер в формате **CMS (Cryptographic Message Syntax)**, RFC 5652. Внешне это контейнер PKCS#7: один объект `ContentInfo` с типом `id-signedData` (pkcs7-signedData).

Формат используется для списков пининга сертификатов (certificate pinning list): в одном контейнере хранятся сертификаты и опционально подпись.

## Структура контейнера (по выводу OpenSSL)

```
CMS_ContentInfo:
  contentType: pkcs7-signedData (1.2.840.113549.1.7.2)
  d.signedData:
    version: 1
    digestAlgorithms:
      algorithm: sha256 (2.16.840.1.101.3.4.2.1)
    encapContentInfo:
      eContentType: pkcs7-data (1.2.840.113549.1.7.1)
      eContent: [OCTET STRING] — последовательность PEM-блоков сертификатов
    certificates: [0] IMPLICIT SET OF Certificate (в данном файле — пусто)
    signerInfos: SET OF SignerInfo (1 подписант)
```

## Детали pinning list (контейнер PKCS#7)

Данные ниже получены утилитой **p7-analyzer** для файла `internal_services_skids_and_certs.p7` (отчёт в формате JSON: `./p7-analyzer -format json -output report-p7.json pining-list/internal_services_skids_and_certs.p7`).

1. **Формат на диске**: PEM с границами `-----BEGIN CMS-----` / `-----END CMS-----`. Тело — base64-кодированный DER одного `ContentInfo`.
2. **SignedData** (по выводу p7-analyzer):

   - **version**: 1
   - **contentType**: pkcs7-signedData (1.2.840.113549.1.7.2)
   - **eContentType**: pkcs7-data (1.2.840.113549.1.7.1)
   - **eContentSize**: 10 537 байт
   - **eContent**: неструктурированные данные — текст вида `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`, повторённый для нескольких сертификатов. Список пининга хранится в виде PEM-цепочек внутри eContent.
3. **certificates** (поле CMS SignedData): в данном контейнере массив **пустой** (0 сертификатов). Все сертификаты списка пининга находятся только в **eContent** в виде PEM-текста.
4. **eContentPEMCerts** (сертификаты, извлечённые из eContent): **10** сертификатов. По данным p7-analyzer:

   - **Издатель сертификатов ролей**: CN=T-Box MQTT Broker ver.2.1.1, O=JSC KAMA, C=RU.
   - **Роли (Subject CN)**: access, accessList, diagnostics, hardware, network, serviceTool, syncClient, telematics, upgrade — все изданы T-Box MQTT Broker, срок действия 2026-01-23 … 2027-01-23, алгоритм ключа ECDSA.
   - **Сертификат брокера**: CN=T-Box MQTT Broker ver.2.1.1, O=JSC KAMA, C=RU; издатель CN=ATOM Inc. Stage Intermediate RU CA R1, OU=IT, O=ATOM Inc., L=Moscow, ST=Moscow, C=RU; срок 2025-08-27 … 2030-08-26, ECDSA.
5. **signerInfos**: один подписант (signersCount: 1), с подписью и атрибутами (contentType, messageDigest и т.д.).
6. **Цель формата**: список SKID и сертификатов для пининга внутренних сервисов (в т.ч. роли JSC KAMA и T-Box MQTT Broker). Контейнер подписан, целостность и происхождение можно проверять через CMS.

## Проверка через OpenSSL

Просмотр структуры:

```bash
openssl cms -cmsout -in pining-list/internal_services_skids_and_certs.p7 -inform PEM -print
```

Извлечение сертификатов из CMS (из поля certificates):

```bash
openssl cms -cmsout -in pining-list/internal_services_skids_and_certs.p7 -inform PEM -print_certs
```

## Инструкция по использованию утилиты p7-analyzer от Atom Ca Team


Для анализа таких контейнеров добавлена отдельная утилита **p7-analyzer**, которая:

- читает файл .p7 (PEM с `BEGIN CMS`/`END CMS` или DER);
- разбирает ContentInfo → SignedData;
- выводит: contentType, version, digestAlgorithms, encapContentInfo (тип и размер eContent);
- извлекает и выводит сертификаты из `SignedData.certificates`;
- при необходимости извлекает PEM-сертификаты из eContent (если eContent — текст с `-----BEGIN CERTIFICATE-----`);
- выводит подписантов (SignerInfo), привязывает сертификат подписанта по SubjectKeyIdentifier/issuerAndSerialNumber.

Запуск:

```bash
go run ./cmd/p7-analyzer [опции] pining-list/internal_services_skids_and_certs.p7
```

Опции выгрузки сертификатов (по аналогии с registry-analyzer):

| Опция                              | Описание                                                                                                                              |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `-export-certs-dir <дир>`          | Каждый сертификат из SignedData.certificates в отдельный PEM (имя: cert-N или по подписанту)    |
| `-export-all-certs`                   | Все сертификаты (SignedData + eContent PEM) в один PEM-файл с именем контейнера (file.p7 → file.pem) |
| `-export-econtent-certs-dir <дир>` | Каждый сертификат из eContent (PEM) в отдельный PEM в указанную директорию (econtent-N.pem)   |
| `-export-signer-cert`                 | Сертификат подписанта в PEM-файл с именем контейнера_signer.pem                                     |

Прочие опции: `-format text|json|pem`, `-output <файл>`, `-no-color`, `-color auto|always|never` (см. `p7-analyzer -h`).

### Формат JSON и поле `pem`

При `-format json` (например `-format json -output report.json файл.p7`) отчёт содержит:

- **contentType**, **version**, **eContentType**, **eContentSize**, **signersCount** — метаданные контейнера;
- **certificates** — массив сертификатов из SignedData.certificates (если есть);
- **eContentPEMCerts** — массив сертификатов, извлечённых из eContent (PEM-текст).

В каждом элементе массивов **certificates** и **eContentPEMCerts** выводится поле **`pem`** — полный PEM-блок сертификата (`-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`). Его можно сохранять в `.pem` или передавать в OpenSSL/код без дополнительного кодирования. Остальные поля: `subject`, `issuer`, `serial`, `notBefore`, `notAfter`, `keyAlgorithm`; у элементов `certificates` дополнительно — `subjectKeyId`, `isSigner`.

---

**ATOM CA Team 2025**
