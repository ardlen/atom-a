# Инструкция по использованию утилиты registry-builder от Atom CA Team

Утилита **registry-builder** создаёт реестры в формате ATOM-PKCS12-REGISTRY (контейнеры `.p12`) с подписанным содержимым. Структура соответствует спецификации [registry.asn1](../registry.asn1) и эталонным реестрам (owner_registry.p12, IVI_Certificate_registry.p12, Driver_Certificate_registry.p12).

---

## Содержание

- [Назначение](#назначение)
- [Сборка и запуск](#сборка-и-запуск)
- [Синтаксис командной строки](#синтаксис-командной-строки)
- [Формат конфигурационного файла](#формат-конфигурационного-файла)
- [Подписант контейнера](#подписант-контейнера)
- [Атрибуты подписанта (VIN, VER, UID)](#атрибуты-подписанта-vin-ver-uid)
- [SafeBags — содержимое реестра](#safebags--содержимое-реестра)
- [Примеры использования](#примеры-использования)
- [Проверка созданного реестра](#проверка-созданного-реестра)
- [Типичные ошибки](#типичные-ошибки)

---

## Назначение

- Собрать PFX-контейнер с **SignedData**: подписант (один сертификат + ключ), список сертификатов в **SafeBags** (eContent), атрибуты подписанта (VIN, VER, UID).
- Имя выходного файла (например `sgw-my-registry.p12`, `sgw-IVI_Certificate_registry.p12`).
- Все пути в конфиге задаются относительно текущей рабочей директории при запуске утилиты.

---

## Сборка и запуск

**Сборка бинарника** (из корня репозитория):

```bash
go build -o registry-builder ./cmd/registry-builder
```

**Минимальный запуск:**

```bash
./registry-builder -config <путь_к_config.json> -output sgw-<имя>.p12
```

Оба параметра обязательны. Без префикса `sgw-` в имени выходного файла утилита завершится с ошибкой.

---

## Синтаксис командной строки

| Параметр | Описание                                                                                                                   | Обязательный |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `-config`      | Путь к JSON-файлу конфигурации (signerCert, signerKey, vin, verTimestamp, verVersion, uid, safeBags)         | да                     |
| `-output`      | Путь к выходному файлу реестра;**имя файла должно начинаться с `sgw-`** | да                     |

Пример:

```bash
./registry-builder -config config.json -output sgw-my-registry.p12
./registry-builder -config config-ivi.json -output sgw-IVI_Certificate_registry.p12
```

---

## Формат конфигурационного файла

Конфиг — один JSON-объект со следующими полями.

### Верхний уровень

| Поле         | Тип       | Описание                                                                                                                  |
| ---------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `signerCert`   | строка | Путь к PEM-файлу сертификата подписанта контейнера                                       |
| `signerKey`    | строка | Путь к PEM-файлу приватного ключа подписанта (ECDSA P-256)                                     |
| `vin`          | строка | Идентификатор транспортного средства (VIN) для атрибута подписанта         |
| `verTimestamp` | строка | Время для атрибута VER (формат RFC3339, например `2024-01-01T00:00:00Z`)                          |
| `verVersion`   | число   | Номер версии для атрибута VER                                                                               |
| `uid`          | строка | Идентификатор подписанта (UID), строка произвольного формата (DN, hex и т.д.) |
| `safeBags`     | массив | Список мешков SafeBag: сертификат + атрибуты (roleName, сроки роли, localKeyID)            |

### Элемент массива `safeBags`

| Поле          | Тип       | Описание                                                                                                                                         |
| ----------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cert`          | строка | Путь к PEM-файлу сертификата X.509 для данного мешка                                                                 |
| `roleName`      | строка | Имя роли (например `delegate`, `not_delegate`, `IVI-first-regular`)                                                                 |
| `roleNotBefore` | строка | Начало срока действия роли (RFC3339)                                                                                              |
| `roleNotAfter`  | строка | Окончание срока действия роли (RFC3339)                                                                                        |
| `localKeyID`    | строка | Идентификатор ключа в hex (обычно SubjectKeyIdentifier сертификата); может быть пустой строкой |

Пустые `roleNotBefore`/`roleNotAfter` или пустой `localKeyID` допустимы; соответствующие атрибуты в мешке тогда не добавляются.

**Пример минимального конфига** (один подписант, два SafeBag):

```json
{
  "signerCert": "certs/signer.pem",
  "signerKey": "certs/signer-key.pem",
  "vin": "EAY2AT0MPS2013376",
  "verTimestamp": "2024-01-01T00:00:00Z",
  "verVersion": 100,
  "uid": "CN=Client A,O=KAMA,C=RU",
  "safeBags": [
    {
      "cert": "certs/driver.pem",
      "roleName": "delegate",
      "roleNotBefore": "2026-01-15T17:40:20Z",
      "roleNotAfter": "2027-01-15T17:40:20Z",
      "localKeyID": "019c09447a0375eb95628f92456dbb9c"
    },
    {
      "cert": "certs/passenger.pem",
      "roleName": "not_delegate",
      "roleNotBefore": "2026-01-15T17:40:20Z",
      "roleNotAfter": "2027-01-15T17:40:20Z",
      "localKeyID": "019c09447a037d96ac545d632f29bb9d"
    }
  ]
}
```

---

## Подписант контейнера

- **Подписант** — тот, кто подписывает весь контейнер (SignedData). Его сертификат помещается в `SignedData.certificates`, а идентификатор (SubjectKeyIdentifier) — в `SignerInfo.sid`.
- Требуется **сертификат** (PEM) и **приватный ключ** (PEM, ECDSA P-256). Утилита не генерирует ключи; их нужно подготовить отдельно (OpenSSL или свой скрипт).

**Варианты получения подписанта:**

1. **Собственная генерация** (например скрипт `scripts/generate_certs.sh`) — создаётся пара ключ + сертификат с нужным Subject (например `CN=Owner Registry Signer`, `CN=IVI-Certificate`).
2. **Сертификат из другого реестра** — если нужен подписант, совпадающий с одним из сертификатов уже существующего реестра (например sgw-my-registry.p12), используют тот же PEM сертификата и ключа, которые использовались при сборке того реестра. Пример: подписант sgw-IVI — сертификат IVI-Certificate из sgw-my-registry (SafeBag [3]); в конфиге указывают `certs/ivi.pem` и `certs/ivi-key.pem`.
3. **Экспорт из существующего .p12** — утилита **registry-analyzer** может выгрузить только **сертификат** подписанта (`-export-signer-cert`). Приватный ключ из контейнера ATOM-PKCS12-REGISTRY не извлекается (его там нет); для подписи нового реестра тем же субъектом нужен отдельно сохранённый ключ или новая пара с тем же CN.

---

## Атрибуты подписанта (VIN, VER, UID)

Они попадают в `SignerInfo.authenticatedAttributes` и подписываются вместе с `contentType` и `messageDigest`:

- **VIN** — идентификатор транспортного средства (строка).
- **VER** — версия: время (`verTimestamp`) + номер (`verVersion`); в конфиге задаются отдельно.
- **UID** — идентификатор подписанта (строка; может быть DN, hex, email и т.д.).

Формат даты/времени для VER: RFC3339 (`2024-01-01T00:00:00Z`). Если `verTimestamp` пустой, атрибут VER в подписи может не включаться или кодироваться с нулевым временем (поведение зависит от реализации).

---

## SafeBags — содержимое реестра

Каждый элемент `safeBags` в конфиге задаёт один мешок в eContent (SafeContents):

- **cert** — путь к PEM сертификата. Сертификат кладётся в CertBag; в мешок добавляются атрибуты `roleName`, `roleValidityPeriod` (из `roleNotBefore`/`roleNotAfter`) и при необходимости `localKeyID`.
- **localKeyID** — строка в hex (без префикса `0x`). Обычно это SubjectKeyIdentifier сертификата. Удобно подставлять значение, полученное скриптом генерации сертификатов или командой:
  ```bash
  openssl x509 -in cert.pem -noout -ext subjectKeyIdentifier | sed 's/.*=//;s/://g' | tr 'A-F' 'a-f'
  ```

Пути в `cert` — относительные к текущей рабочей директории при запуске `registry-builder`.

---

## Примеры использования

### 1. Реестр типа owner_registry (sgw-my-registry.p12)

Полный набор: один подписант (Owner Registry Signer) и четыре SafeBag (Driver, Passenger, IVI, Mobile-Driver).

**Шаг 1 — генерация сертификатов и конфига:**

```bash
./scripts/generate_certs.sh
```

Скрипт создаёт каталог `certs/` (подписант + четыре сертификата для SafeBags) и обновляет `config.json` с актуальными `localKeyID` (SubjectKeyIdentifier).

**Шаг 2 — сборка реестра:**

```bash
./registry-builder -config config.json -output sgw-my-registry.p12
```

**Шаг 3 — проверка:**

```bash
./registry-analyzer sgw-my-registry.p12
```

---

### 2. Реестр типа IVI (sgw-IVI_Certificate_registry.p12)

Содержимое и атрибуты как у IVI_Certificate_registry.p12; подписант — сертификат IVI-Certificate из того же набора, что и в sgw-my-registry (один из SafeBag sgw-my-registry).

**Подготовка сертификатов SafeBags из эталонного IVI:**

Флаги утилиты указывать **перед** именем файла:

```bash
mkdir -p ivi-certs
./registry-analyzer -export-safebag-certs-dir ivi-certs IVI_Certificate_registry.p12
```

В `ivi-certs/` появятся PEM-файлы сертификатов (например `IVI-first-regular_2ec84cc1.pem`, `IVI-second-regular_598f7a8e.pem`).

**Подписант из sgw-my-registry (IVI-Certificate):**

В `config-ivi.json` указать сертификат и ключ IVI-Certificate из каталога `certs/`, созданного скриптом `generate_certs.sh`:

```json
{
  "signerCert": "certs/ivi.pem",
  "signerKey": "certs/ivi-key.pem",
  "vin": "EAY2AT0MPS2013376",
  "verTimestamp": "2024-01-01T00:00:00Z",
  "verVersion": 100,
  "uid": "019c09447a03731f91afa6403987dac2",
  "safeBags": [
    {
      "cert": "ivi-certs/IVI-first-regular_2ec84cc1.pem",
      "roleName": "IVI-first-regular",
      "roleNotBefore": "2026-01-15T17:40:21Z",
      "roleNotAfter": "2027-01-15T17:40:21Z",
      "localKeyID": "019c09447fa47228851b7b602ec84cc1"
    },
    {
      "cert": "ivi-certs/IVI-second-regular_598f7a8e.pem",
      "roleName": "IVI-second-regular",
      "roleNotBefore": "2026-01-11T17:40:21Z",
      "roleNotAfter": "2027-01-20T17:40:21Z",
      "localKeyID": "019c09447fb47e9289b508ec598f7a8e"
    }
  ]
}
```

**Сборка:**

```bash
./registry-builder -config config-ivi.json -output sgw-IVI_Certificate_registry.p12
```

Чтобы подписант sgw-IVI совпадал с сертификатом из уже собранного sgw-my-registry (в т.ч. по Serial), сначала соберите sgw-my-registry, затем sgw-IVI, не перезапуская между ними `generate_certs.sh`.

---

### 3. Подписант — сертификат из другого реестра

Если подписантом должен быть один из сертификатов, входящих в другой реестр (например sgw-my-registry.p12):

- Используйте тот же PEM сертификата и ключа, которые использовались при сборке этого реестра. Для sgw-my-registry это файлы из `certs/` (signer.pem/signer-key.pem или ivi.pem/ivi-key.pem и т.д.).
- В конфиге укажите пути к этим файлам в полях `signerCert` и `signerKey`.

Сертификат из .p12 можно только экспортировать (registry-analyzer `-export-signer-cert` или сертификаты из SafeBags в директорию); приватный ключ из ATOM-PKCS12-REGISTRY не извлекается, его нужно хранить отдельно.

---

## Проверка созданного реестра

После сборки рекомендуется проверить структуру и подписанта:

```bash
./registry-analyzer sgw-my-registry.p12
./registry-analyzer sgw-IVI_Certificate_registry.p12
```

Убедитесь, что:

- В блоке **Certificates** есть сертификат подписанта и он помечен как «подписант контейнера».
- В блоке **Подписант контейнера** отображается Subject, Serial и KeyAlg ожидаемого сертификата.
- В **SafeContents** перечислены все мешки с нужными roleName, roleValidityPeriod и localKeyID.

Дополнительно можно выгрузить сертификаты в PEM и проверить их через OpenSSL (см. [docs/OPENSSL_VERIFY.md](OPENSSL_VERIFY.md)).

---

## Типичные ошибки

| Ситуация                                                                                          | Причина                                                                                                                 | Решение                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Имя выходного файла должно начинаться с sgw-`                        | В `-output` указано имя без префикса `sgw-`                                                          | Задайте имя вида `sgw-<имя>.p12`.                                                                                                                                                          |
| `signer cert: no PEM block` / `signer key: no PEM block`                                              | Файл не PEM или путь неверный                                                                             | Проверьте пути в конфиге и что файлы в формате PEM (заголовки `-----BEGIN CERTIFICATE-----` / `-----BEGIN EC PRIVATE KEY-----`).                           |
| `signer key: ... not an ECDSA key`                                                                      | Указан не ECDSA-ключ                                                                                               | Утилита поддерживает только ECDSA P-256 для подписи. Сгенерируйте ключ, например:`openssl ecparam -name prime256v1 -genkey -noout -out key.pem`. |
| `SubjectKeyIdentifier required`                                                                         | У сертификата подписанта нет расширения Subject Key Identifier                              | При создании сертификата добавьте расширения, например:`-addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid:always`.                     |
| `safeBags[i] cert ... no such file`                                                                     | Неверный путь к PEM сертификата SafeBag                                                                | Проверьте поле `cert` в конфиге; пути считаются относительно текущей директории.                                                             |
| `safeBags[i] localKeyID: ...`                                                                           | Некорректный hex в `localKeyID`                                                                                 | Укажите строку в hex без пробелов (допускается префикс `0x`). Пустая строка допустима.                                                      |
| Подписант не находится в списке сертификатов при анализе | Раньше могла быть ошибка в разборе SID; в актуальной версии исправлено | Обновите код и пересоберите registry-analyzer.                                                                                                                                        |

---

## Связанные документы

- [registry.asn1](../registry.asn1) — спецификация структуры контейнера.
- [WORKFLOW.md](WORKFLOW.md) — пошаговый разбор контейнера и выгрузка данных.
- [OPENSSL_VERIFY.md](OPENSSL_VERIFY.md) — проверка сертификатов через OpenSSL.
- [registry-builder-config.example.json](registry-builder-config.example.json) — пример конфигурации.

---

**ATOM CA Team 2025**
