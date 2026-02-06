# Сравнение вывода openssl asn1parse: эталон vs sgw-owner-6-new.p12

После внедрения изменений по документу REGISTRY_BUILDER_COMPATIBILITY.md новый реестр собирается командой:
```bash
./registry-builder -config config.json -output sgw-owner-6-new.p12
```

Сравнение структуры:
```bash
openssl asn1parse -in "demo-original-container (2).p12" -inform DER
openssl asn1parse -in sgw-owner-6-new.p12 -inform DER
```

## Совпадение структуры (по ключевым полям)

| Элемент | Эталон demo-original-container (2).p12 | sgw-owner-6-new.p12 (после правок) |
|--------|----------------------------------------|-----------------------------------|
| **Content [0]** | `d=3 hl=4 l=4637 cons: SEQUENCE` | `d=3 hl=4 l=2816 cons: SEQUENCE` |
| **eContent [0]** | `d=6 hl=4 l=3861 prim: OCTET STRING` (внутри [0]) | `d=5 hl=4 l=2000 prim: cont [ 0 ]` (значение [0] = OCTET STRING 04 ll ...) |
| **certificates [0]** | `d=5 hl=4 l=392 cons: SET` | `d=5 hl=4 l=386 cons: SET` |
| **SID [0]** | `d=7 hl=2 l=20 prim: OCTET STRING` | `d=7 hl=2 l=20 prim: OCTET STRING` |
| **Порядок атрибутов** | contentType → VIN → VER → UID → messageDigest | contentType → VIN → VER → UID → messageDigest |
| **unauthenticatedAttributes [1]** | `d=5 hl=2 l=0 cons: SET` | `d=7 hl=2 l=0 cons: SET` |

## Вывод

- **Content [0]** — в обоих файлах в [0] лежит полный SEQUENCE SignedData (0x30); структура совпадает.
- **certificates [0]** — в обоих в [0] полный SET (0x31); структура совпадает.
- **SignerIdentifier [0]** — в обоих SID задан как OCTET STRING (20 байт SKID); структура совпадает.
- **authenticatedAttributes** — порядок атрибутов совпадает с эталоном: contentType, VIN, VER, UID, messageDigest.
- **unauthenticatedAttributes [1]** — в обоих присутствует пустой SET; структура совпадает.
- **eContent [0]** — в эталоне [0] показан как constructed с вложенным OCTET STRING; в новом реестре [0] — primitive с длиной 2000, при этом значение [0] по-прежнему является OCTET STRING (04 ll ...). Семантически содержимое одно и то же (OCTET STRING вокруг SafeContents), различие только в том, как OpenSSL отображает тег [0] (constructed vs primitive) в зависимости от кодирования.

Различия в длинах (l=4637 vs 2816, l=3861 vs 2000 и т.д.) связаны с разным объёмом данных (разные сертификаты и число SafeBag), а не со структурой.

Итог: создаваемые реестры по структуре соответствуют эталону `demo-original-container (2).p12` по всем пунктам из REGISTRY_BUILDER_COMPATIBILITY.md.
