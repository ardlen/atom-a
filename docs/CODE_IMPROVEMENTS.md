# Предложения по улучшению и оптимизации утилит

Документ содержит рекомендации по повышению продуктивности использования registry-analyzer и registry-builder, а также улучшения кода и UX.

---

## 1. CLI и UX

### 1.1. Поддержка нескольких файлов (registry-analyzer)

**Текущее состояние:** принимается только один файл `.p12`.

**Предложение:**
```bash
./registry-analyzer *.p12
./registry-analyzer -format json owner.p12 ivi.p12 driver.p12 -output reports/
```

- Режим batch: обработка нескольких файлов с выводом в одну директорию.
- Флаг `-quiet` для подавления stderr при batch (только ошибки).

### 1.2. Флаг `-verify` — проверка подписи

**Предложение:** добавить опцию проверки подписи CMS при разборе:
```bash
./registry-analyzer -verify owner_registry.p12
```

- Проверка messageDigest и encryptedDigest по RFC 5652.
- Вывод: `✓ Подпись валидна` или `✗ Ошибка проверки подписи: ...`.

### 1.3. Флаг `-summary` — краткий вывод

**Предложение:** компактный режим (только VIN, VER, UID, количество сертификатов и SafeBags):
```bash
./registry-analyzer -summary owner_registry.p12
```

### 1.4. Конфиг registry-builder: пути и переменные

**Текущее состояние:** пути в конфиге относительно CWD.

**Предложение:**
- Поддержка переменных `$HOME`, `$PWD` в путях.
- Флаг `-config-dir` — базовая директория для относительных путей в конфиге.
- Валидация конфига до сборки (проверка существования файлов).

### 1.5. Версионирование и `-version`

**Предложение:**
```bash
./registry-analyzer -version
./registry-builder -version
```

- Вывод версии из `go.mod` или встроенной константы.
- Полезно для CI/CD и отладки.

---

## 2. Валидация и обработка ошибок

### 2.1. Валидация конфига (registry-builder)

**Текущее состояние:** ошибки обнаруживаются при чтении файлов.

**Предложение:**
- Проверка обязательных полей (signerCert, signerKey, vin, uid).
- Проверка существования файлов до начала сборки.
- Более понятные сообщения: `signerCert: файл не найден: certs/signer.pem (путь относительно CWD: ...)`.

### 2.2. Валидация сертификатов

**Предложение:**
- Проверка соответствия ключа и сертификата подписанта.
- Проверка SubjectKeyId у сертификатов в SafeBags (если localKeyID не задан).
- Предупреждение о просроченных сертификатах (roleValidityPeriod, notAfter).

### 2.3. Exit-коды

**Предложение:** явные коды выхода для скриптов:
- `0` — успех
- `1` — ошибка аргументов (usage)
- `2` — ошибка чтения/разбора файла
- `3` — ошибка проверки подписи (при -verify)

---

## 3. Оптимизация кода

### 3.1. Избежание повторного парсинга сертификатов

**Где:** `builder.go` — в `marshalSafeContents` для каждого SafeBag при пустом LocalKeyID вызывается `x509.ParseCertificate(in.CertDER)`.

**Предложение:** кэшировать результат или передавать уже распарсенный cert в SafeBagInput (опционально).

### 3.2. Регулярное выражение в sanitizeExportBasename

**Где:** `output.go` — `regexp.MustCompile` вызывается при каждом вызове.

**Предложение:** вынести в package-level `var`:
```go
var sanitizeRE = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
```

### 3.3. Предвыделение срезов

**Где:** `parse.go`, `builder.go` — при итерации по bags/certs используется `append` без предварительного `make` с capacity.

**Предложение:** `bags := make([]SafeBag, 0, len(rest)/estimatedSize)` — для больших реестров снизит количество реаллокаций.

### 3.4. Выделение общих DER-утилит

**Где:** `builder.go` — `marshalUTF8StringValue`, `marshalAttributeSet`, `marshalCertificateSet` дублируют логику кодирования длины DER.

**Предложение:** общая функция `func derEncodeLength(l int) []byte` и использование её во всех местах.

---

## 4. Структура и переиспользование

### 4.1. Разделение CLI и библиотеки

**Предложение:** явный публичный API в `internal/registry`:
- `Parse(der []byte) (*Container, error)` — уже есть.
- `BuildRegistry(...) ([]byte, error)` — уже есть.
- Добавить `Container.VerifySignature() error` для проверки подписи.

Это упростит использование пакета как библиотеки из других проектов.

### 4.2. Пакет `internal/der` для низкоуровневых операций

**Предложение:** вынести `derPrependTLV`, `unwrapOctetStringIfPresent`, кодирование длины в отдельный пакет `internal/der` для повторного использования и тестирования.

---

## 5. Конфигурация registry-builder

### 5.1. Поддержка friendlyName

**Предложение:** добавить поле `friendlyName` в SafeBagConfig для совместимости со стандартным PKCS#12 (если требуется отображение в диалогах выбора сертификата).

### 5.2. Валидация VIN/UID

**Предложение:** опциональная валидация формата (например, VIN — 17 символов по ISO 3779) с предупреждением.

### 5.3. Шаблоны имён выходных файлов

**Предложение:** в конфиге `outputTemplate` для batch-сборки:
```json
"outputTemplate": "registries/{vin}_{role}.p12"
```

---

## 6. Документация и согласованность

### 6.1. p7-analyzer отсутствует

**Текущее состояние:** README и ADR ссылаются на p7-analyzer и internal/cms, но в репозитории их нет.

**Предложение:**
- Либо реализовать p7-analyzer (если требуется).
- Либо обновить README, ADR, REGISTRY_ARCHITECTURE: убрать упоминания p7-analyzer или помечить как «запланировано».

### 6.2. Имя модуля в go.mod

**Текущее:** `github.com/sgw-registry/registry-analyzer` — импорты в коде соответствуют.

**Рекомендация:** при публикации пакета как библиотеки рассмотреть нейтральное имя, например `github.com/sgw-registry/registry`, т.к. пакет содержит и analyzer, и builder.

---

## 7. Тестирование

### 7.1. Интеграционные тесты

**Предложение:**
- Тест на реальном `owner_registry.p12` из репозитория: Parse → ToJSON → сравнение ключевых полей.
- Тест round-trip: BuildRegistry → Parse → сравнение SafeBags, VIN, VER, UID.

### 7.2. Тесты на некорректный ввод

**Предложение:** проверка обработки битых .p12, неполных структур, неверной версии PFX.

### 7.3. Benchmark

**Предложение:**
```go
func BenchmarkParse(b *testing.B) {
    data, _ := os.ReadFile("testdata/owner_registry.p12")
    for i := 0; i < b.N; i++ {
        Parse(data)
    }
}
```

---

## 8. Сборка и распространение

### 8.1. Makefile / Taskfile

**Предложение:** единая точка входа для сборки:
```makefile
build:
	go build -o bin/registry-analyzer ./cmd/registry-analyzer
	go build -o bin/registry-builder ./cmd/registry-builder
test:
	go test ./...
```

### 8.2. Docker-образ (опционально)

**Предложение:** для CI и изолированного запуска:
```dockerfile
FROM golang:1.25-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o registry-analyzer ./cmd/registry-analyzer && \
    go build -o registry-builder ./cmd/registry-builder
FROM alpine:latest
COPY --from=build /app/registry-analyzer /app/registry-builder /usr/local/bin/
ENTRYPOINT ["registry-analyzer"]
```

---

## 9. Приоритеты внедрения

| Приоритет | Улучшение                          | Сложность | Польза        |
|-----------|------------------------------------|-----------|---------------|
| Высокий   | `-version`                         | Низкая    | CI, отладка   |
| Высокий   | Валидация конфига (файлы, поля)    | Средняя   | Меньше ошибок |
| Высокий   | Приведение документации в порядок (p7-analyzer) | Низкая | Согласованность |
| Средний   | `-verify` проверка подписи         | Средняя   | Безопасность  |
| Средний   | Вынести sanitizeRE в package-level | Низкая    | Производительность |
| Средний   | Exit-коды                          | Низкая    | Скрипты       |
| Низкий    | Batch-режим для нескольких файлов  | Средняя   | Автоматизация |
| Низкий    | `-summary`                         | Низкая    | Удобство      |

---

**ATOM CA Team 2025**
