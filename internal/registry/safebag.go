package registry

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf16"

	"crypto/x509"
)

// formatUUID форматирует 16 байт как UUID с дефисами (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

// formatGeneralizedTime преобразует ASN.1 GeneralizedTime (например "20260115174021Z") в формат "2006-01-02 15:04:05".
func formatGeneralizedTime(s string) string {
	t, err := time.Parse("20060102150405Z", s)
	if err != nil {
		t, err = time.Parse("20060102150405.000Z", s)
	}
	if err != nil {
		return s
	}
	return t.Format("2006-01-02 15:04:05")
}

// SafeBagInfo — расшифрованный мешок SafeBag: содержимое CertBag, краткая информация о сертификате (если X.509) и атрибуты мешка.
type SafeBagInfo struct {
	BagId         asn1.ObjectIdentifier
	CertId        asn1.ObjectIdentifier   // тип сертификата из CertBag
	CertType      string                  // человекочитаемое описание типа
	CertSummary   *CertSummary            // краткие данные сертификата, если certValue — X.509
	CertValueLen  int                     // длина сырых байт, если не X.509
	CertValueDER  []byte                  // сырой DER сертификата (для X.509), для выгрузки в PEM
	BagAttributes []BagAttributeValue     // расшифрованные атрибуты мешка (roleName, localKeyID и т.д.)
}

// CertSummary — краткая информация о сертификате X.509 (subject, issuer, serial, срок действия, алгоритм ключа).
type CertSummary struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	KeyAlg    string `json:"keyAlgorithm"`
}

// BagAttributeValue — одно расшифрованное значение атрибута мешка (friendlyName, localKeyID, roleName и т.д.).
type BagAttributeValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParseSafeBagInfo разбирает один SafeBag в SafeBagInfo: извлекает CertBag, при возможности парсит сертификат как X.509 и расшифровывает атрибуты мешка.
func ParseSafeBagInfo(bag SafeBag) (info SafeBagInfo, err error) {
	info.BagId = bag.BagId
	// BagValue — [0] IMPLICIT CertBag: в Bytes может быть content SEQUENCE без 0x30.
	bagValueBytes := bag.BagValue.Bytes
	if len(bagValueBytes) == 0 && len(bag.BagValue.FullBytes) > 0 {
		bagValueBytes = bag.BagValue.FullBytes
	}
	if len(bagValueBytes) > 0 && bagValueBytes[0] != 0x30 {
		bagValueBytes = derPrependTLV(0x30, bag.BagValue.Bytes)
	}
	var cb CertBag
	_, err = asn1.Unmarshal(bagValueBytes, &cb)
	if err != nil {
		return info, err
	}
	info.CertId = cb.CertId
	info.CertType = CertTypeName(cb.CertId)
	// CertValue: [0] IMPLICIT OCTET STRING → Bytes = cert DER; иначе может быть 04 ll ... (EXPLICIT)
	certDER := cb.CertValue.Bytes
	certDER = unwrapOctetStringIfPresent(certDER)
	info.CertValueLen = len(certDER)
	if cert, err := x509.ParseCertificate(certDER); err == nil {
		info.CertSummary = &CertSummary{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			Serial:    cert.SerialNumber.Text(16),
			NotBefore: cert.NotBefore.Format("2006-01-02"),
			NotAfter:  cert.NotAfter.Format("2006-01-02"),
			KeyAlg:    cert.PublicKeyAlgorithm.String(),
		}
		info.CertValueDER = append([]byte(nil), certDER...) // копия для выгрузки в PEM
	}
	for _, a := range bag.BagAttributes {
		vals := DecodeBagAttributeValues(a)
		info.BagAttributes = append(info.BagAttributes, vals...)
	}
	return info, nil
}

// DecodeBagAttributeValues расшифровывает атрибуты мешка PKCS#12 (friendlyName, localKeyID, roleName, roleValidityPeriod и т.д.).
func DecodeBagAttributeValues(a Attribute) []BagAttributeValue {
	var out []BagAttributeValue
	name := OIDToAtomName(a.AttrType)
	if name == "" {
		name = a.AttrType.String()
	}
	for _, rv := range a.AttrValues {
		val := decodeBagAttrValue(a.AttrType, rv.Bytes, rv.FullBytes)
		out = append(out, BagAttributeValue{Name: name, Value: val})
	}
	return out
}

// decodeBagAttrValue по OID и сырым байтам возвращает строковое значение атрибута мешка.
func decodeBagAttrValue(oid asn1.ObjectIdentifier, content, full []byte) string {
	switch {
	case oid.Equal(OIDPKCS9FriendlyName):
		// В PKCS#12 friendlyName часто кодируется как BMPString (тег 0x1e, UCS-2 big-endian).
		if len(full) > 0 && full[0] == 0x1e && len(content) >= 2 {
			return decodeBMPString(content)
		}
		return string(content)
	case oid.Equal(OIDPKCS9LocalKeyID):
		raw := content
		if len(raw) == 0 && len(full) > 0 {
			raw = unwrapOctetStringIfPresent(full)
		}
		if len(raw) == 16 {
			return formatUUID(raw)
		}
		return hex.EncodeToString(raw)
	case oid.Equal(OIDAtomRoleName):
		return string(content)
	case oid.Equal(OIDAtomRoleValidityPeriod):
		// Период действия роли: SEQUENCE { notBeforeTime GeneralizedTime, notAfterTime GeneralizedTime }.
		var seq struct {
			NotBefore asn1.RawValue
			NotAfter  asn1.RawValue
		}
		raw := full
		if len(raw) == 0 {
			raw = content
		}
		if _, err := asn1.Unmarshal(raw, &seq); err == nil {
			nb := formatGeneralizedTime(string(seq.NotBefore.Bytes))
			na := formatGeneralizedTime(string(seq.NotAfter.Bytes))
			return fmt.Sprintf("notBefore=%s, notAfter=%s", nb, na)
		}
		return hex.EncodeToString(content)
	default:
		if len(content) > 0 && utf8Valid(content) {
			return string(content)
		}
		return hex.EncodeToString(content)
	}
}

// decodeBMPString декодирует BMPString (UCS-2 big-endian, по 2 байта на символ) в строку Go.
func decodeBMPString(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
	}
	return string(utf16.Decode(u))
}

// utf8Valid проверяет, является ли байтовая последовательность допустимой UTF-8.
func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c < 0x80 {
			continue
		}
		if c >= 0xc2 && c <= 0xdf && i+1 < len(b) {
			i++
			continue
		}
		if c >= 0xe0 && c <= 0xef && i+2 < len(b) {
			i += 2
			continue
		}
		if c >= 0xf0 && c <= 0xf4 && i+3 < len(b) {
			i += 3
			continue
		}
		return false
	}
	return true
}
