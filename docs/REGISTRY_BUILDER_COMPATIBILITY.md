# Сравнение структур реестров и рекомендации для registry-builder

**Цель:** привести выход registry-builder к структуре, идентичной эталонному реестру `demo-original-container (2).p12`.

**Сравниваемые файлы:**
- **Эталон:** `demo-original-container (2).p12`
- **Текущий вывод builder:** `sgw-owner-6-new.p12`

Анализ выполнен с помощью `openssl asn1parse -in <file> -inform DER` и просмотра кода `internal/registry/builder.go`.

---

## 1. Отличия по полям (DER-структура)

### 1.1. ContentInfo.content [0] (SignedData)

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Кодирование | **EXPLICIT:** в [0] лежит полный TLV SignedData (тег **0x30** SEQUENCE + длина + содержимое) | **IMPLICIT:** в [0] лежит только содержимое SEQUENCE (без тега 0x30), первый байт — INTEGER version (0x02 0x01) |
| OpenSSL asn1parse | `d=3 hl=4 l=4637 cons: SEQUENCE` | `d=3 hl=2 l=1 prim: INTEGER :01` |

**Рекомендация для registry-builder:** в `content [0]` класть **полный** SignedData (0x30 + длина + содержимое), а не `derSkipTagAndLength(signedDataDER)`. То есть использовать `Bytes: signedDataDER` в `Content`.

---

### 1.2. EncapsulatedContentInfo.eContent [0]

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Кодирование | **EXPLICIT OCTET STRING:** значение [0] — полный OCTET STRING (тег **0x04** + длина + байты SafeContents) | **IMPLICIT:** значение [0] — примитивный тег 0x80, байты SafeContents **без** обёртки 0x04 |
| OpenSSL asn1parse | `d=6 hl=4 l=3861 prim: OCTET STRING` | `d=4 hl=4 l=1996 prim: cont [ 0 ]` (примитивное значение) |

**Рекомендация для registry-builder:** в `eContent [0]` класть **OCTET STRING** (0x04 + длина + safeContentsDER), а не сырые байты SafeContents. То есть не использовать примитивный 0x80; кодировать eContent как `asn1.Marshal(safeContentsDER)` и этот результат (04 ll ...) помещать в значение [0].

---

### 1.3. SignedData.certificates [0]

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Кодирование | В [0] лежит **полный SET** (тег **0x31** + длина + элементы SET OF Certificate) | В [0] лежит только **длина + содержимое** SET (тег 0x31 срезан: `certSetDER[1:]`) |
| OpenSSL asn1parse | `d=5 hl=4 l=392 cons: SET` внутри [0] | Первый байт значения [0] — длина (0x81/0x82), не 0x31; парсеры могут интерпретировать как другой тег |

**Рекомендация для registry-builder:** в `Certificates [0]` класть **полный** SET (0x31 + длина + содержимое), т.е. `Bytes: certSetDER`, а не `certSetDER[1:]`.

---

### 1.4. SignerIdentifier (sid) [0] subjectKeyIdentifier

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Кодирование | **[0] EXPLICIT OCTET STRING:** значение [0] — OCTET STRING (0x04 + длина + 20 байт SKID) | **[0] IMPLICIT:** примитивный тег 0x80 + длина + 20 байт SKID (без 0x04) |
| OpenSSL asn1parse | `d=7 hl=2 l=20 prim: OCTET STRING` внутри [0] | `d=5 hl=2 l=20 prim: cont [ 0 ]` (примитивное) |

**Рекомендация для registry-builder:** кодировать SID как [0] **EXPLICIT OCTET STRING**: сначала упаковать SKID в OCTET STRING (`asn1.Marshal(ski)`), затем поместить этот TLV в значение контекстного тега [0]. Не использовать текущий формат 0x80 + raw bytes.

---

### 1.5. authenticatedAttributes [0]

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Тип | SET OF Attribute (тег **0x31**) | SET OF Attribute (0x31) |
| Содержимое [0] | Полный SET (0x31 + длина + элементы) | Полный SET (0x31 + длина + элементы) — **совпадает** |

Здесь структура уже совпадает: в обоих случаях в [0] — полный SET (0x31 ...). Менять ничего не требуется.

---

### 1.6. Порядок атрибутов в authenticatedAttributes (SET OF)

В SET OF порядок по DER не задан семантически, но для побайтовой идентичности с эталоном порядок элементов должен совпадать.

| Эталон demo | Текущий builder |
|-------------|------------------|
| 1) contentType | 1) contentType |
| 2) VIN (1.3.6.1.4.1.99999.1.1) | 2) messageDigest |
| 3) VER (1.3.6.1.4.1.99999.1.2) | 3) VIN |
| 4) UID (1.3.6.1.4.1.99999.1.3) | 4) VER |
| 5) **messageDigest** | 5) UID |

В эталоне **messageDigest идёт последним**. В builder список собирается как contentType, messageDigest, VIN, VER, UID, затем применяется **сортировка по DER** (`sortAttributesByDER`), из‑за чего порядок меняется.

**Рекомендация для registry-builder:** для совместимости с эталоном задать **фиксированный порядок** атрибутов: contentType, VIN, VER, UID, messageDigest — и **не сортировать** SET OF по DER (либо сортировать так, чтобы получался именно этот порядок).

---

### 1.7. unauthenticatedAttributes [1]

| Аспект | demo-original-container (2).p12 | sgw-owner-6-new.p12 |
|--------|----------------------------------|----------------------|
| Наличие | Присутствует: контекстный тег [1], значение — пустой SET (0x31 0x00) | Поле опционально; при отсутствии в структуре Go тег [1] не кодируется |

**Рекомендация для registry-builder:** если нужна идентичная структура, добавлять в SignerInfo поле **unauthenticatedAttributes [1]** с пустым SET: закодировать `[]byte{0x31, 0x00}` и поместить в `UnauthenticatedAttributes.Bytes` (или выставить RawValue с тегом 1 и этим значением), чтобы в DER всегда появлялся `cont [ 1 ]` с пустым SET.

---

## 2. Сводная таблица изменений в registry-builder

| Компонент | Текущее поведение | Требуемое для идентичности эталону |
|-----------|-------------------|-------------------------------------|
| **Content [0]** | IMPLICIT SignedData (content без 0x30) | EXPLICIT: полный SignedData (0x30 + длина + content) |
| **eContent [0]** | IMPLICIT (0x80 + raw SafeContents) | EXPLICIT OCTET STRING (0x04 + длина + SafeContents) |
| **certificates [0]** | IMPLICIT (length+content SET, без 0x31) | Полный SET (0x31 + длина + content) |
| **sid [0]** | IMPLICIT (0x80 + raw SKID) | EXPLICIT OCTET STRING (0x04 + длина + SKID) |
| **authenticatedAttributes [0]** | Полный SET (0x31...) | Без изменений |
| **Порядок атрибутов** | Сортировка по DER | Фиксированный: contentType, VIN, VER, UID, messageDigest |
| **unauthenticatedAttributes [1]** | Не кодируется | Пустой SET (0x31 0x00) в [1] |

---

## 3. Рекомендуемый порядок внедрения

1. **certificates [0]** — класть полный `certSetDER` (уже обсуждалось для OpenSSL).
2. **content [0]** — класть полный `signedDataDER` (для анализаторов, ожидающих 0x30).
3. **eContent [0]** — кодировать как OCTET STRING (04 ll ...) в значении [0].
4. **sid [0]** — кодировать как OCTET STRING (04 ll ...) в значении [0].
5. **Порядок атрибутов** — убрать сортировку по DER и зафиксировать порядок: contentType, VIN, VER, UID, messageDigest.
6. **unauthenticatedAttributes [1]** — при необходимости добавить пустой SET в [1].

После этих изменений структура реестра, создаваемого registry-builder, будет соответствовать эталону `demo-original-container (2).p12` по перечисленным полям и порядку атрибутов.
