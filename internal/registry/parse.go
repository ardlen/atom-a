// Package registry обеспечивает разбор и сборку контейнеров ATOM-PKCS12-REGISTRY (.p12).
// Контейнер — PFX (PKCS#12) с authSafe = ContentInfo(SignedData). eContent декодируется как SafeContents (SEQUENCE OF SafeBag).
// Подписант идентифицируется по SubjectKeyIdentifier в SignerInfo.sid.
package registry

import (
	"encoding/asn1"
	"fmt"

	"crypto/x509"
)

// Container — результат разбора контейнера ATOM-PKCS12-REGISTRY.
//
// Содержит:
//   - PFXVersion, ContentType — метаданные оболочки PFX
//   - SignedData — сырая структура CMS
//   - Certificates — сертификаты из SignedData.certificates (подписант + CA)
//   - SafeBags, SafeBagInfos — мешки из eContent (сертификаты ролей Driver, IVI и т.д.)
//   - Signers — SignerInfo с атрибутами (VIN, VER, UID в authenticatedAttributes)
type Container struct {
	PFXVersion   int
	ContentType  asn1.ObjectIdentifier
	SignedData   *SignedData
	Certificates []*x509.Certificate
	SafeBags     []SafeBag
	SafeBagInfos []SafeBagInfo // расшифрованные SafeBag: CertBag и атрибуты
	Signers      []SignerInfo
}

// derPrependTLV добавляет DER-тег и длину к content.
// Используется при разборе IMPLICIT-кодирования: когда в контекстный тег [0] записано только содержимое без TLV,
// восстанавливаем полный TLV для корректного asn1.Unmarshal (например, SignedData без 0x30, SET без 0x31).
func derPrependTLV(tag byte, content []byte) []byte {
	if len(content) == 0 {
		return nil
	}
	l := len(content)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l <= 255 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{tag}, lenBytes...), content...)
}

// Parse разбирает DER-кодированный файл .p12 (PFX с authSafe = ContentInfo(SignedData)).
//
// Этапы:
//  1. Разбор PFX, проверка version=3 и contentType=pkcs7-signedData
//  2. Разбор SignedData (с восстановлением TLV при IMPLICIT content [0])
//  3. Извлечение сертификатов из certificates [0] (SET OF Certificate)
//  4. Декодирование eContent как SafeContents, разбор SafeBag и атрибутов
//
// Поддерживается как полный TLV в content [0], так и IMPLICIT (только содержимое без тега).
func Parse(der []byte) (*Container, error) {
	var pfx PFX
	rest, err := asn1.Unmarshal(der, &pfx)
	if err != nil {
		return nil, fmt.Errorf("PFX unmarshal: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing bytes after PFX")
	}
	if pfx.Version != 3 {
		return nil, fmt.Errorf("unsupported PFX version: %d", pfx.Version)
	}

	ci := pfx.AuthSafe
	if !ci.ContentType.Equal(OIDPKCS7SignedData) {
		return nil, fmt.Errorf("authSafe contentType is not pkcs7-signedData: %v", ci.ContentType)
	}

	// [0] IMPLICIT SignedData: при записи в Content только content SEQUENCE без 0x30 — восстанавливаем TLV
	signedDataDER := ci.Content.Bytes
	if len(signedDataDER) > 0 && signedDataDER[0] != 0x30 {
		signedDataDER = derPrependTLV(0x30, ci.Content.Bytes)
	}
	var sd SignedData
	_, err = asn1.Unmarshal(signedDataDER, &sd)
	if err != nil {
		return nil, fmt.Errorf("SignedData unmarshal: %w", err)
	}

	c := &Container{
		PFXVersion:  pfx.Version,
		ContentType: ci.ContentType,
		SignedData:  &sd,
		Signers:     sd.SignerInfos,
	}

	// Сертификаты: [0] IMPLICIT — в Bytes может быть SET без тега 0x31, восстанавливаем только тег.
	setBytes := sd.Certificates.Bytes
	if len(setBytes) > 0 && setBytes[0] != 0x31 {
		setBytes = append([]byte{0x31}, sd.Certificates.Bytes...)
	}
	if len(setBytes) > 0 {
		certs, err := parseCertificateSet(setBytes)
		if err != nil {
			return nil, fmt.Errorf("certificates: %w", err)
		}
		c.Certificates = certs
	}

	// eContent: [0] IMPLICIT OCTET STRING → Bytes = SafeContents; иначе EXPLICIT → 04 ll ...
	eContent := unwrapOctetStringIfPresent(sd.EncapContentInfo.EContent.Bytes)
	if sd.EncapContentInfo.EContentType.Equal(OIDPKCS7Data) && len(eContent) > 0 {
		bags, err := parseSafeContents(eContent)
		if err != nil {
			return nil, fmt.Errorf("SafeContents: %w", err)
		}
		c.SafeBags = bags
		for _, bag := range bags {
			info, err := ParseSafeBagInfo(bag)
			if err != nil {
				continue
			}
			c.SafeBagInfos = append(c.SafeBagInfos, info)
		}
	}

	return c, nil
}

// parseCertificateSet разбирает SET OF Certificate (каждый элемент — OCTET STRING с DER-сертификатом X.509).
func parseCertificateSet(setBytes []byte) ([]*x509.Certificate, error) {
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(setBytes, &raw)
	if err != nil {
		return nil, err
	}
	if raw.Tag != asn1.TagSet {
		return nil, fmt.Errorf("expected SET, got tag %d", raw.Tag)
	}
	var certs []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		var certOctet asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &certOctet)
		if err != nil {
			return nil, err
		}
		if certOctet.Class == asn1.ClassUniversal && certOctet.Tag == asn1.TagOctetString {
			c, err := x509.ParseCertificate(certOctet.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
		}
	}
	return certs, nil
}

// parseSafeContents разбирает SEQUENCE OF SafeBag из байтов eContent.
func parseSafeContents(content []byte) ([]SafeBag, error) {
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(content, &seq)
	if err != nil {
		return nil, err
	}
	if seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE, got tag %d", seq.Tag)
	}
	var bags []SafeBag
	rest := seq.Bytes
	for len(rest) > 0 {
		var bag SafeBag
		var err error
		rest, err = asn1.Unmarshal(rest, &bag)
		if err != nil {
			return nil, err
		}
		bags = append(bags, bag)
	}
	return bags, nil
}

// ParseAuthenticatedAttributes разбирает authenticatedAttributes [0] из SignerInfo (SET OF Attribute).
func ParseAuthenticatedAttributes(raw []byte) ([]Attribute, error) {
	var set asn1.RawValue
	_, err := asn1.Unmarshal(raw, &set)
	if err != nil {
		return nil, err
	}
	var attrs []Attribute
	rest := set.Bytes
	for len(rest) > 0 {
		var a Attribute
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// unwrapOctetStringIfPresent возвращает payload OCTET STRING.
// Если d начинается с 0x04 (тег OCTET STRING), снимает обёртку и возвращает значение; иначе возвращает d как есть.
// Нужно для eContent [0] и CertBag.certValue [0]: могут быть EXPLICIT (04 ll val) или IMPLICIT (сырые байты).
func unwrapOctetStringIfPresent(d []byte) []byte {
	if len(d) < 2 || d[0] != 0x04 {
		return d
	}
	skip := 2
	l := int(d[1])
	if d[1]&0x80 != 0 {
		nlen := int(d[1] & 0x7f)
		if 2+nlen > len(d) {
			return d
		}
		l = 0
		for i := 0; i < nlen; i++ {
			l = l<<8 + int(d[2+i])
		}
		skip = 2 + nlen
	}
	if skip+l <= len(d) {
		return d[skip : skip+l]
	}
	return d
}

// SignerAttributes возвращает расшифрованные атрибуты из SignerInfo.authenticatedAttributes [0].
// Включает contentType, messageDigest, VIN, VER, UID, roleName, roleValidityPeriod (ATOM OID 1.3.6.1.4.1.99999.1.x).
func SignerAttributes(si *SignerInfo) ([]Attribute, error) {
	if len(si.AuthenticatedAttributes.Bytes) == 0 {
		return nil, nil
	}
	// [0] IMPLICIT: в Bytes лежит (length+content) SET, тег 0x31 был срезан; восстанавливаем только тег.
	attrsBytes := si.AuthenticatedAttributes.Bytes
	if attrsBytes[0] != 0x31 {
		attrsBytes = append([]byte{0x31}, si.AuthenticatedAttributes.Bytes...)
	}
	return ParseAuthenticatedAttributes(attrsBytes)
}
