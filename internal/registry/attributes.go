package registry

import (
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"time"
)

// AttrValue — одно расшифрованное значение атрибута для вывода (имя OID и человекочитаемое/сырое значение).
type AttrValue struct {
	Name  string // краткое имя (VIN, UID и т.д.)
	Value string // человекочитаемое значение
	Raw   string // hex или сырое значение (например, для messageDigest)
}

// DecodeAttributeValues возвращает человекочитаемые значения для атрибута (ATOM и стандартные OID).
// Используется для атрибутов подписанта в SignerInfo.authenticatedAttributes.
func DecodeAttributeValues(a Attribute) []AttrValue {
	var out []AttrValue
	name := OIDToAtomName(a.AttrType)
	if name == "" {
		name = a.AttrType.String()
	}
	for _, rv := range a.AttrValues {
		// FullBytes нужны для корректного разбора вложенных типов (например, GeneralizedTime в SEQUENCE).
		raw := rv.FullBytes
		if len(raw) == 0 {
			raw = rv.Bytes
		}
		decoded := decodeSingleAttrValue(a.AttrType, raw, name)
		out = append(out, decoded)
	}
	return out
}

// decodeSingleAttrValue разбирает одно значение атрибута по OID и возвращает AttrValue для вывода.
func decodeSingleAttrValue(oid asn1.ObjectIdentifier, raw []byte, name string) AttrValue {
	av := AttrValue{Name: name}
	switch {
	case oid.Equal(OIDAtomVIN), oid.Equal(OIDAtomUID), oid.Equal(OIDAtomRoleName):
		var s string
		if _, err := asn1.Unmarshal(raw, &s); err == nil {
			av.Value = s
		} else {
			av.Value = string(raw)
		}
	case oid.Equal(OIDAtomVER):
		// VER — SEQUENCE { GeneralizedTime (тег 24), INTEGER }: разбираем SEQUENCE, затем элементы.
		var seq asn1.RawValue
		var err error
		if _, err = asn1.Unmarshal(raw, &seq); err != nil || seq.Tag != asn1.TagSequence {
			av.Raw = hex.EncodeToString(raw)
			break
		}
		rest := seq.Bytes
		var tsRaw, verRaw asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &tsRaw); err != nil {
			av.Raw = hex.EncodeToString(raw)
			break
		}
		if _, err = asn1.Unmarshal(rest, &verRaw); err != nil {
			av.Raw = hex.EncodeToString(raw)
			break
		}
		ts := string(tsRaw.Bytes)
		var ver int
		asn1.Unmarshal(verRaw.FullBytes, &ver)
		if t, err := time.Parse("20060102150405Z", ts); err == nil {
			av.Value = fmt.Sprintf("timestamp=%s, version=%d", t.Format(time.RFC3339), ver)
		} else {
			av.Value = fmt.Sprintf("timestamp=%s, version=%d", ts, ver)
		}
	case oid.Equal(OIDAtomRoleValidityPeriod):
		// Период действия роли: SEQUENCE { notBeforeTime GeneralizedTime, notAfterTime GeneralizedTime }.
		var seq struct {
			NotBefore string
			NotAfter  string
		}
		if _, err := asn1.Unmarshal(raw, &seq); err == nil {
			nb := formatGeneralizedTime(seq.NotBefore)
			na := formatGeneralizedTime(seq.NotAfter)
			av.Value = fmt.Sprintf("notBefore=%s, notAfter=%s", nb, na)
		} else {
			av.Raw = hex.EncodeToString(raw)
		}
	case oid.Equal(OIDPKCS9MessageDigest):
		// Сырые данные могут быть полным TLV (04 len val) или только значением; для вывода берём значение.
		var octet []byte
		if _, err := asn1.Unmarshal(raw, &octet); err == nil {
			av.Value = hex.EncodeToString(octet)
		} else {
			av.Value = hex.EncodeToString(raw)
		}
	case oid.Equal(OIDPKCS9ContentType):
		var o asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(raw, &o); err == nil {
			av.Value = o.String()
			if o.Equal(OIDPKCS7Data) {
				av.Value = "pkcs7-data"
			}
		}
	case oid.Equal(OIDPKCS9LocalKeyID):
		av.Value = hex.EncodeToString(raw)
	default:
		// UTF8String или OCTET STRING: пробуем как строку, иначе выводим hex.
		var s string
		if _, err := asn1.Unmarshal(raw, &s); err == nil {
			av.Value = s
		} else {
			av.Value = hex.EncodeToString(raw)
		}
	}
	return av
}

// SignerRoleName возвращает значение атрибута roleName из authenticatedAttributes данного SignerInfo.
// Используется для имени файла при выгрузке сертификата подписанта (например -export-certs-dir).
func SignerRoleName(si *SignerInfo) string {
	attrs, err := SignerAttributes(si)
	if err != nil {
		return ""
	}
	for _, a := range attrs {
		for _, v := range DecodeAttributeValues(a) {
			if v.Name == "roleName" && v.Value != "" {
				return v.Value
			}
		}
	}
	return ""
}
