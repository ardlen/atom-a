package cms

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

// unwrapOctetString снимает обёртку OCTET STRING (0x04 ll ...) если есть.
func unwrapOctetString(d []byte) []byte {
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

// ParseCMS разбирает DER одного ContentInfo (pkcs7-signedData) и возвращает Container.
func ParseCMS(der []byte) (*Container, error) {
	var ci ContentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing bytes after ContentInfo")
	}
	if !ci.ContentType.Equal(OIDPKCS7SignedData) {
		return nil, fmt.Errorf("contentType is not pkcs7-signedData: %v", ci.ContentType)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}

	eContent := unwrapOctetString(sd.EncapContentInfo.EContent.Bytes)
	c := &Container{
		ContentType:  ci.ContentType,
		Version:      sd.Version,
		EContentType: sd.EncapContentInfo.EContentType,
		EContentSize: len(eContent),
		EContentRaw:  eContent,
		SignerInfos:  sd.SignerInfos,
	}

	// Сертификаты из SignedData.certificates ([0] IMPLICIT SET OF Certificate)
	setBytes := sd.Certificates.Bytes
	if len(setBytes) > 0 {
		if setBytes[0] != 0x31 {
			setBytes = append([]byte{0x31}, setBytes...)
		}
		certs, err := parseCertificateSet(setBytes)
		if err != nil {
			// В некоторых контейнерах [0] может быть пустой или с другой структурой — не ломаем разбор
			c.Certificates = nil
		} else {
			c.Certificates = certs
		}
	}

	// PEM-сертификаты из eContent (если eContent — текст с -----BEGIN CERTIFICATE-----)
	if len(eContent) > 0 {
		certs := parsePEMCerts(eContent)
		c.EContentCerts = certs
	}

	// Найти сертификат подписанта по SID (SubjectKeyIdentifier)
	if len(c.SignerInfos) > 0 {
		c.SignerCert = findSignerCert(&c.SignerInfos[0], c.Certificates, c.EContentCerts)
	}

	return c, nil
}

// ParseCMSFromPEM читает PEM с границами -----BEGIN CMS----- / -----END CMS----- или -----BEGIN PKCS7----- / -----END PKCS7----- и разбирает тело как DER ContentInfo.
func ParseCMSFromPEM(pemBytes []byte) (*Container, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		// Попробуем как сырой DER
		return ParseCMS(pemBytes)
	}
	// Тип может быть "CMS", "PKCS7", "PKCS#7" и т.д.
	return ParseCMS(block.Bytes)
}

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

// parsePEMCerts извлекает все PEM-блоки CERTIFICATE из data.
func parsePEMCerts(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, c)
			}
		}
		data = rest
		if len(rest) == 0 {
			break
		}
	}
	return certs
}

// extractSKID извлекает SubjectKeyIdentifier из SignerInfo.sid ([0] IMPLICIT OCTET STRING или IssuerAndSerialNumber).
func extractSKID(sid asn1.RawValue) []byte {
	if len(sid.Bytes) == 0 {
		return nil
	}
	// [0] IMPLICIT OCTET STRING: SID.Bytes может быть уже payload (контекстный тег 0).
	if sid.Tag == 0 && len(sid.Bytes) > 0 && sid.Bytes[0] != 0x04 && sid.Bytes[0] != 0x80 {
		return sid.Bytes
	}
	ski := sid.Bytes
	if len(ski) > 0 && (ski[0] == 0x04 || ski[0] == 0x80) {
		var octet []byte
		if _, err := asn1.Unmarshal(ski, &octet); err == nil {
			return octet
		}
	}
	return sid.Bytes
}

func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}

// findSignerCert ищет сертификат по SID (SubjectKeyIdentifier или IssuerAndSerialNumber) в certificates и eContentCerts.
func findSignerCert(si *SignerInfo, certs, eContentCerts []*x509.Certificate) *x509.Certificate {
	if c := findSignerBySKID(si, certs, eContentCerts); c != nil {
		return c
	}
	return findSignerByIssuerAndSerial(si.SID, certs, eContentCerts)
}

func findSignerBySKID(si *SignerInfo, certs, eContentCerts []*x509.Certificate) *x509.Certificate {
	ski := extractSKID(si.SID)
	if len(ski) == 0 {
		return nil
	}
	for _, c := range certs {
		if len(c.SubjectKeyId) > 0 && bytesEqual(c.SubjectKeyId, ski) {
			return c
		}
	}
	for _, c := range eContentCerts {
		if len(c.SubjectKeyId) > 0 && bytesEqual(c.SubjectKeyId, ski) {
			return c
		}
	}
	return nil
}

// extractSerialFromIssuerAndSerial находит в DER IssuerAndSerialNumber значение serialNumber (последний INTEGER).
func extractSerialFromIssuerAndSerial(der []byte) []byte {
	var last []byte
	for i := 0; i+2 <= len(der); i++ {
		if der[i] != 0x02 {
			continue
		}
		l := int(der[i+1])
		start := i + 2
		if der[i+1]&0x80 != 0 {
			if der[i+1] == 0x81 && i+3 <= len(der) {
				l = int(der[i+2])
				start = i + 3
			} else {
				continue
			}
		}
		if l >= 1 && l <= 32 && start+l <= len(der) {
			last = der[start : start+l]
		}
	}
	return last
}

func findSignerByIssuerAndSerial(sid asn1.RawValue, certs, eContentCerts []*x509.Certificate) *x509.Certificate {
	if len(sid.Bytes) == 0 {
		return nil
	}
	// Извлекаем serialNumber: в DER это последний INTEGER (02 ll [bytes]); ищем 02 14 (INTEGER len 20)
	serialBytes := extractSerialFromIssuerAndSerial(sid.Bytes)
	if len(serialBytes) == 0 {
		return nil
	}
	serial := new(big.Int).SetBytes(serialBytes)
	all := append(certs, eContentCerts...)
	for _, c := range all {
		if c.SerialNumber == nil {
			continue
		}
		if serial.Cmp(c.SerialNumber) == 0 {
			return c
		}
		// Нормализованное сравнение (одинаковая длина, ведущие нули)
		const maxLen = 32
		b1 := serial.FillBytes(make([]byte, maxLen))
		b2 := c.SerialNumber.FillBytes(make([]byte, maxLen))
		if bytes.Equal(b1, b2) {
			return c
		}
	}
	return nil
}
