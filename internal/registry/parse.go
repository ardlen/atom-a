package registry

import (
	"encoding/asn1"
	"fmt"

	"crypto/x509"
)

// Container — результат разбора контейнера ATOM-PKCS12-REGISTRY.
// Содержит версию PFX, тип содержимого, SignedData, список сертификатов,
// мешки SafeBag (сырые и расшифрованные), информацию о подписантах.
type Container struct {
	PFXVersion   int
	ContentType  asn1.ObjectIdentifier
	SignedData   *SignedData
	Certificates []*x509.Certificate
	SafeBags     []SafeBag
	SafeBagInfos []SafeBagInfo // расшифрованные SafeBag: CertBag и атрибуты
	Signers      []SignerInfo
}

// Parse разбирает DER-кодированный файл .p12 (PFX с authSafe = ContentInfo(SignedData))
// и возвращает структуру Container с сертификатами, мешками и подписантами.
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

	var sd SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("SignedData unmarshal: %w", err)
	}

	c := &Container{
		PFXVersion:  pfx.Version,
		ContentType: ci.ContentType,
		SignedData:  &sd,
		Signers:     sd.SignerInfos,
	}

	// Сертификаты: [0] EXPLICIT SET OF Certificate (каждый Certificate — OCTET STRING с DER X.509).
	if len(sd.Certificates.Bytes) > 0 {
		certs, err := parseCertificateSet(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificates: %w", err)
		}
		c.Certificates = certs
	}

	// eContent (encapContentInfo): тип pkcs7-data, значение — OCTET STRING = SafeContents (SEQUENCE OF SafeBag).
	if sd.EncapContentInfo.EContentType.Equal(OIDPKCS7Data) && len(sd.EncapContentInfo.EContent) > 0 {
		bags, err := parseSafeContents(sd.EncapContentInfo.EContent)
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
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}
	return attrs, nil
}

// SignerAttributes возвращает расшифрованные атрибуты подписанта из SignerInfo ([0] authenticatedAttributes).
func SignerAttributes(si *SignerInfo) ([]Attribute, error) {
	if len(si.AuthenticatedAttributes.Bytes) == 0 {
		return nil, nil
	}
	return ParseAuthenticatedAttributes(si.AuthenticatedAttributes.Bytes)
}
