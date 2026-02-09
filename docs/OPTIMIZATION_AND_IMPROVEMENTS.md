# Анализ кода проекта: оптимизация и рекомендации

Документ содержит результаты анализа кодовой базы sgw-registry (registry-analyzer, registry-builder, p7-analyzer) с рекомендациями по оптимизации, устранению дублирования, улучшению обработки ошибок и тестированию. Дополняет [CODE_IMPROVEMENTS.md](CODE_IMPROVEMENTS.md).

---

## 1. Дублирование кода и общие утилиты

### 1.1. Функция `unwrapOctetString` / `unwrapOctetStringIfPresent`

**Где:** Логика снятия обёртки OCTET STRING (0x04 ll ...) реализована дважды:

- `internal/registry/parse.go`: `unwrapOctetStringIfPresent`
- `internal/cms/parse.go`: `unwrapOctetString`

**Рекомендация:** Вынести в общий пакет `internal/der` (или `internal/asn1util`) одну функцию, например `UnwrapOctETString(data []byte) []byte`, и использовать её в `registry` и `cms`. Это упростит поддержку и тесты.

### 1.2. Функция `derPrependTLV` (DER-тег и длина)

**Где:** В `internal/registry/parse.go` — `derPrependTLV(tag, content)`. Аналогичная логика кодирования длины DER есть в `internal/registry/builder.go` (marshalUTF8StringValue, marshalCertificateSet и т.д.).

**Рекомендация:** Ввести в `internal/der` (или в `registry`) общие функции:

- `DerPrependTLV(tag byte, content []byte) []byte`
- `DerEncodeLength(l int) []byte` — для использования в builder при сборке TLV

Использовать их в parse и builder, чтобы не дублировать расчёт длин (short/long form).

### 1.3. Функция `isTerminal`

**Где:** Одинаковая реализация в:

- `cmd/registry-analyzer/main.go`
- `cmd/p7-analyzer/main.go`

**Рекомендация:** Вынести в общий пакет, например `internal/cli` или `pkg/terminal`:

```go
// IsTerminal возвращает true, если f — терминал (для цветного вывода).
func IsTerminal(f *os.File) bool
```

Подключить в обоих `main.go`. При появлении третьей утилиты с цветным выводом дублирование исчезнет.

### 1.4. Логика выбора цвета (useColor)

**Где:** В обоих анализаторах повторяется выражение:

```go
useColor := !*noColor && (*colorFlag == "always" || (*colorFlag != "never" && isTerminal(os.Stdout)))
```

**Рекомендация:** Вынести в `internal/cli`: например, `UseColor(noColor bool, colorFlag string, w *os.File) bool`. Единая точка изменения поведения (auto/always/never + TTY).

---

## 2. Производительность и аллокации

### 2.1. Регулярное выражение в `sanitizeExportBasename`

**Где:** `internal/registry/output.go` — при каждом вызове выполняется `regexp.MustCompile(\`[^a-zA-Z0-9._-]+\`)`.

**Рекомендация:** Вынести в переменную уровня пакета:

```go
var reSanitizeExportBasename = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
```

Использовать её в `sanitizeExportBasename`. Снижает аллокации и разбор регулярного выражения при массовом экспорте сертификатов.

### 2.2. Предвыделение срезов при разборе

**Где:**

- `internal/registry/parse.go`: разбор SET OF Certificate, SEQUENCE OF SafeBag — срезы растут через `append` без начальной capacity.
- `internal/cms/parse.go`: `parseCertificateSet`, `parsePEMCerts` — то же.

**Рекомендация:** Задать разумную начальную ёмкость, где возможно, например:

```go
certs := make([]*x509.Certificate, 0, 16)           // или оценка из длины rest
bags := make([]SafeBag, 0, len(rest)/estimatedSize)
```

Особенно полезно для больших реестров и pinning-list с десятками сертификатов.

### 2.3. Повторный парсинг сертификата в registry-builder

**Где:** `internal/registry/builder.go`, `marshalSafeContents`: при пустом `LocalKeyID` для каждого SafeBag вызывается `x509.ParseCertificate(in.CertDER)` только чтобы взять `SubjectKeyId`.

**Рекомендация:** Кэшировать результат (например, один раз распарсить в `loadSafeBags` и передавать уже готовый `SubjectKeyId` в конфиге) или расширить `SafeBagInput` опциональным полем `SubjectKeyId []byte`, чтобы при известном SKID не парсить сертификат повторно.

---

## 3. Обработка ошибок и выход из программы

### 3.1. Единые коды выхода (exit codes)

**Где:** Во всех трёх `cmd` используется только `os.Exit(1)` при любой ошибке.

**Рекомендация:** Ввести константы и использовать их в скриптах/CI:

- `0` — успех
- `1` — ошибка аргументов (usage, неверный флаг)
- `2` — ошибка ввода-вывода или разбора (файл не найден, неверный формат)
- `3` — ошибка проверки подписи (при будущем флаге `-verify`)

Например: `os.Exit(exitCodeUsage)` / `exitCodeParse` и т.д. Документировать в `README` и в `-h`.

### 3.2. Валидация конфига registry-builder до сборки

**Где:** Ошибки (нет файла сертификата, неверный JSON) обнаруживаются в процессе загрузки.

**Рекомендация:** Перед вызовом `BuildRegistry` выполнить валидацию:

- Проверка обязательных полей: `signerCert`, `signerKey`, `vin`, `uid`.
- Проверка существования файлов по путям из конфига.
- При ошибке — чёткое сообщение с путём и контекстом (например: «signerCert: файл не найден: certs/signer.pem»).

Улучшит UX и упростит отладку.

### 3.3. Сообщения об ошибках на русском и английском

**Где:** Сообщения в stderr смешаны (русский/английский).

**Рекомендация:** Для консистентности выбрать один язык для пользовательских сообщений или ввести простой механизм локализации (переменная окружения или флаг). Не блокирует оптимизацию, но улучшает согласованность.

---

## 4. Структура пакетов и API

### 4.1. Пакет `internal/der` (или `internal/asn1util`)

**Рекомендация:** Создать общий пакет для низкоуровневых DER/ASN.1 операций:

- `UnwrapOctetString(data []byte) []byte`
- `PrependTLV(tag byte, content []byte) []byte`
- `EncodeLength(l int) []byte` (опционально)

Использовать в `internal/registry` и `internal/cms`, не дублируя логику. Покрыть unit-тестами на граничные случаи (пустой ввод, длинная форма длины).

### 4.2. Пакет `internal/cli` для общих CLI-утилит

**Рекомендация:** Вынести:

- `IsTerminal(f *os.File) bool`
- `UseColor(noColor bool, colorFlag string, w *os.File) bool`
- При желании — общие константы exit-кодов.

Тогда `cmd/registry-analyzer` и `cmd/p7-analyzer` останутся тонкими обёртками над логикой и выводом.

### 4.3. Цвета и иконки в cms и registry

**Где:** В `internal/registry/terminal.go` и `internal/cms/output.go` заданы свои наборы ANSI-кодов и иконок. Семантика похожа (Bold, Dim, Cyan, заголовки секций).

**Рекомендация:** Долгосрочно рассмотреть общий пакет `internal/terminal` (или использовать уже существующий `registry/terminal`) с экспортом констант и, при необходимости, функцией форматирования секции. Тогда p7-analyzer мог бы импортировать общие стили из одного места. Не обязательно делать в первом шаге — только при росте числа утилит с цветным выводом.

---

## 5. Тестирование

### 5.1. Тесты для internal/cms

**Где:** В `internal/registry` есть `parse_test.go`, `builder_test.go`; в `internal/cms` тестов нет.

**Рекомендация:** Добавить хотя бы:

- `internal/cms/parse_test.go`: разбор фиксированного DER/PEM (маленький CMS с одним подписантом и пустым certificates), проверка полей Container и извлечения сертификатов из eContent.
- Тест на pinning-list из репозитория (`pining-list/internal_services_skids_and_certs.p7`): Parse → проверка SignersCount, количества eContentCerts, наличия SignerCert (по SID).

### 5.2. Интеграционные тесты

**Рекомендация:** Как в CODE_IMPROVEMENTS.md:

- Round-trip для registry: BuildRegistry → Parse → сравнение ключевых полей (VIN, UID, количество SafeBags, сертификаты).
- Анализ реального .p12 из репозитория: Parse → ToJSON → проверка наличия ожидаемых полей и типов.

### 5.3. Тесты на некорректный ввод

**Рекомендация:** Проверять устойчивость:

- Обрезанный или случайный бинарный файл вместо .p12/.p7.
- PFX с неверной версией или contentType.
- CMS с пустым или повреждённым certificates (уже частично учтено в cms — при ошибке parseCertificateSet список обнуляется).

---

## 6. Безопасность и валидация

### 6.1. Проверка соответствия ключа и сертификата подписанта

**Где:** registry-builder принимает отдельно `signerCert` и `signerKey`; явной проверки соответствия нет.

**Рекомендация:** После загрузки PEM проверять, что публичный ключ сертификата совпадает с ключом из файла (например, через сравнение координат ECDSA или `cert.PublicKey.(*ecdsa.PublicKey)` и `key.Public()`). При несовпадении возвращать ошибку до сборки.

### 6.2. Размер ввода при разборе

**Где:** Parse и ParseCMS принимают весь срез в памяти; для очень больших файлов это может быть нежелательно.

**Рекомендация:** Для текущего сценария (реестры и pinning-list) допустимо оставить как есть. При появлении требований к файлам большого размера — рассмотреть лимит размера (например, константа maxFileSize) или потоковый разбор только заголовков.

---

## 7. Документация и согласованность

### 7.1. README и список утилит

**Где:** p7-analyzer уже реализован; CODE_IMPROVEMENTS.md ранее помечал его как отсутствующий.

**Рекомендация:** Убедиться, что в README и в других документах (ADR, REGISTRY_ARCHITECTURE) перечислены все три утилиты (registry-analyzer, registry-builder, p7-analyzer) с краткими примерами запуска и ссылкой на PKCS7_CMS_ANALYSIS.md для .p7.

### 7.2. Версионирование и флаг `-version`

**Рекомендация:** Как в CODE_IMPROVEMENTS.md — добавить во все три утилиты поддержку `-version` (версия из go.mod или встроенная константа). Полезно для CI и отладки.

---

## 8. Приоритеты внедрения

| Приоритет | Рекомендация | Сложность | Эффект |
|-----------|--------------|-----------|--------|
| Высокий | Вынести `regexp` в package-level в `registry/output.go` | Низкая | Меньше аллокаций при экспорте |
| Высокий | Общий пакет `internal/der` + перенос `unwrapOctetString` и `derPrependTLV` | Средняя | Меньше дублирования, проще тесты |
| Высокий | Добавить тесты для `internal/cms` (parse, eContent, SignerCert) | Средняя | Регрессии, уверенность при рефакторинге |
| Высокий | Флаг `-version` для всех трёх утилит | Низкая | CI, отладка |
| Средний | Вынести `isTerminal` и логику `useColor` в `internal/cli` | Низкая | DRY, единообразие CLI |
| Средний | Единые exit-коды (1/2/3) и документирование в README | Низкая | Скрипты, автоматизация |
| Средний | Валидация конфига registry-builder (поля, существование файлов) | Средняя | Меньше запутанных ошибок |
| Средний | Предвыделение срезов в parse (registry + cms) | Низкая | Меньше реаллокаций на больших входах |
| Низкий | Кэширование/опциональный SKID в SafeBagInput (builder) | Средняя | Меньше повторного парсинга сертификатов |
| Низкий | Общий пакет для цветов/иконок (registry + cms) | Низкая | Единый стиль вывода |

---

## 9. Связь с CODE_IMPROVEMENTS.md

Рекомендации из [CODE_IMPROVEMENTS.md](CODE_IMPROVEMENTS.md) остаются в силе, в частности:

- Поддержка нескольких файлов (batch) и флаг `-quiet` для registry-analyzer.
- Флаг `-verify` для проверки подписи CMS.
- Флаг `-summary` для краткого вывода.
- Расширение конфига registry-builder (переменные окружения, `-config-dir`, шаблоны имён).
- Makefile/Taskfile для сборки и тестов.
- Интеграционные и benchmark-тесты.

Настоящий документ дополняет их анализом дублирования (unwrapOctetString, isTerminal, useColor), конкретными местами в коде и приоритизацией с учётом уже реализованного p7-analyzer и пакета cms.

---

**Дата анализа:** 2025  
**Версия репозитория:** с поддержкой p7-analyzer и internal/cms
