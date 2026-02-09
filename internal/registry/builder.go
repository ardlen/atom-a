package registry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// SafeBagInput — входные данные для одного SafeBag в eContent.
// Используется при сборке: CertDER — DER X.509; RoleName, RoleNotBefore/After — атрибуты мешка; LocalKeyID — обычно SubjectKeyId.
type SafeBagInput struct {
	CertDER       []byte // DER сертификата X.509
	RoleName      string
	RoleNotBefore time.Time
	RoleNotAfter  time.Time
	LocalKeyID    []byte // обычно SubjectKeyId или произвольный идентификатор
}

// SignerAttrs — атрибуты подписанта для SignerInfo.authenticatedAttributes [0].
// Хранятся на уровне подписанта (ADR-007), не в eContent или SafeBag.
type SignerAttrs struct {
	VIN          string
	VERTimestamp time.Time
	VERVersion   int
	UID          string
}

// BuildRegistry собирает реестр ATOM-PKCS12-REGISTRY в формате, совместимом с эталоном (ADR-011).
//
// Этапы:
//  1. marshalSafeContents — SafeContents (SEQUENCE OF SafeBag) с roleName, roleValidityPeriod, localKeyID
//  2. encapContentInfo — eContentType=pkcs7-data, eContent [0]=EXPLICIT OCTET STRING
//  3. messageDigest — SHA-256 над eContent (safeContentsDER)
//  4. authenticatedAttributes — contentType, VIN, VER, UID, messageDigest (сортировка по DER)
//  5. signAuthenticatedAttributes — ECDSA P-256 над DER(authenticatedAttributes)
//  6. certificates [0] — полный SET TLV; SignerInfo с sid=[0] EXPLICIT OCTET STRING (SubjectKeyId)
//
// Возвращает DER-кодированный PFX (version=3, authSafe=ContentInfo с полным SignedData TLV в content [0]).
func BuildRegistry(signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey, safeBags []SafeBagInput, attrs SignerAttrs) ([]byte, error) {
	if signerCert == nil || signerKey == nil {
		return nil, fmt.Errorf("signer cert and key required")
	}

	// 1. Собрать SafeContents (SEQUENCE OF SafeBag)
	safeContentsDER, err := marshalSafeContents(safeBags)
	if err != nil {
		return nil, fmt.Errorf("marshal SafeContents: %w", err)
	}

	// 2. encapContentInfo: eContentType = pkcs7-data, eContent [0] EXPLICIT OCTET STRING OPTIONAL (registry.asn1)
	// EXPLICIT => [0] constructed (0xA0), content = full OCTET STRING TLV (0x04 + length + SafeContents)
	eContentOctet, err := asn1.Marshal(safeContentsDER)
	if err != nil {
		return nil, fmt.Errorf("eContent OCTET STRING: %w", err)
	}
	encapContentInfo := EncapsulatedContentInfo{
		EContentType: OIDPKCS7Data,
		EContent:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: eContentOctet, IsCompound: true},
	}

	// 3. Хеш eContent для messageDigest (подписывается именно eContent в контексте encapContentInfo)
	// В CMS digest вычисляется над eContentType + eContent; для простоты берём хеш сырого eContent (OCTET STRING value)
	contentToDigest := safeContentsDER
	digest := sha256.Sum256(contentToDigest)

	// 4. Собрать authenticatedAttributes (SET OF Attribute): contentType, messageDigest, VIN, VER, UID
	authAttrsDER, err := marshalAuthenticatedAttributes(digest[:], attrs)
	if err != nil {
		return nil, fmt.Errorf("authenticatedAttributes: %w", err)
	}

	// 5. Подписать DER(authenticatedAttributes) — по RFC 5652 подпись над DER-кодировкой атрибутов
	sigDER, err := signAuthenticatedAttributes(signerKey, authAttrsDER)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// 6. certificates [0] EXPLICIT SET OF Certificate
	certSetDER, err := marshalCertificateSet([][]byte{signerCert.Raw})
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}

	// 7. SignerInfo: SID = [0] subjectKeyIdentifier
	sidDER, err := marshalSubjectKeyIdentifier(signerCert.SubjectKeyId)
	if err != nil {
		return nil, fmt.Errorf("SignerIdentifier: %w", err)
	}

	// [0] IMPLICIT Attributes: полный SET OF (0x31 ll ...)
	authAttrsRaw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: authAttrsDER, IsCompound: true}
	// [1] unauthenticatedAttributes: пустой SET (0x31 0x00) — как в эталоне
	emptyUnauthSet := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{0x31, 0x00}, IsCompound: true}
	signerInfo := SignerInfo{
		Version:                    1,
		SID:                        asn1.RawValue{FullBytes: sidDER},
		DigestAlgorithm:            AlgorithmIdentifier{Algorithm: OIDSHA256},
		AuthenticatedAttributes:    authAttrsRaw,
		DigestEncryptionAlgorithm:  AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256},
		EncryptedDigest:            sigDER,
		UnauthenticatedAttributes:  emptyUnauthSet,
	}

	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{{Algorithm: OIDSHA256}},
		EncapContentInfo: encapContentInfo,
		// [0] EXPLICIT CertificateSet: полный SET (0x31 + длина + content) — как в эталоне
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: certSetDER, IsCompound: true},
		SignerInfos:      []SignerInfo{signerInfo},
	}

	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}

	// [0] EXPLICIT SignedData: в тег кладём полный TLV SignedData (0x30 + длина + content) — как в эталоне demo-original-container
	contentRaw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: signedDataDER, IsCompound: true}
	contentInfo := ContentInfo{
		ContentType: OIDPKCS7SignedData,
		Content:     contentRaw,
	}

	pfx := PFX{
		Version:  3,
		AuthSafe: contentInfo,
	}

	return asn1.Marshal(pfx)
}

// OID алгоритмов (дополнительно к oid.go).
var (
	OIDSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

func marshalSafeContents(inputs []SafeBagInput) ([]byte, error) {
	var bags []SafeBag
	for _, in := range inputs {
		// certValue [0] EXPLICIT OCTET STRING (registry.asn1): [0] constructed (0xA0), content = OCTET STRING (0x04 + cert DER)
		certValueOctet, err := asn1.Marshal(in.CertDER)
		if err != nil {
			return nil, err
		}
		cb := CertBag{
			CertId:    OIDX509Certificate,
			CertValue: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: certValueOctet, IsCompound: true},
		}
		cbDER, err := asn1.Marshal(cb)
		if err != nil {
			return nil, err
		}
		// bagValue [0] EXPLICIT CertBag (registry.asn1): в [0] — полный TLV CertBag (0x30 + длина + content)
		bagValue := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: cbDER, IsCompound: true}

		var bagAttrs []Attribute
		if in.RoleName != "" {
			bagAttrs = append(bagAttrs, attrUTF8String(OIDAtomRoleName, in.RoleName))
		}
		if !in.RoleNotBefore.IsZero() || !in.RoleNotAfter.IsZero() {
			nb := in.RoleNotBefore.UTC().Format("20060102150405Z")
			na := in.RoleNotAfter.UTC().Format("20060102150405Z")
			bagAttrs = append(bagAttrs, attrRoleValidityPeriod(nb, na))
		}
		localKeyID := in.LocalKeyID
		if len(localKeyID) == 0 {
			if cert, err := x509.ParseCertificate(in.CertDER); err == nil && len(cert.SubjectKeyId) > 0 {
				localKeyID = cert.SubjectKeyId
			}
		}
		if len(localKeyID) > 0 {
			bagAttrs = append(bagAttrs, attrOctetString(OIDPKCS9LocalKeyID, localKeyID))
		}
		bagAttrs = sortAttributesByDER(bagAttrs)

		bags = append(bags, SafeBag{
			BagId:         OIDCertBag,
			BagValue:      bagValue,
			BagAttributes: bagAttrs,
		})
	}
	return asn1.Marshal(SafeContents(bags))
}

// marshalUTF8StringValue кодирует строку как ASN.1 UTF8String (тег 0x0C). Go asn1.Marshal(string)
// по умолчанию даёт PrintableString (0x13), а registry.asn1 требует UTF8String для RoleName, VIN, UID.
func marshalUTF8StringValue(s string) []byte {
	b := []byte(s)
	l := len(b)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l < 256 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{0x0C}, lenBytes...), b...)
}

func attrUTF8String(oid asn1.ObjectIdentifier, s string) Attribute {
	return Attribute{AttrType: oid, AttrValues: []asn1.RawValue{{FullBytes: marshalUTF8StringValue(s)}}}
}

func attrOctetString(oid asn1.ObjectIdentifier, b []byte) Attribute {
	val, _ := asn1.Marshal(b)
	return Attribute{AttrType: oid, AttrValues: []asn1.RawValue{{FullBytes: val}}}
}

func attrRoleValidityPeriod(notBefore, notAfter string) Attribute {
	nb, _ := time.Parse("20060102150405Z", notBefore)
	na, _ := time.Parse("20060102150405Z", notAfter)
	type roleValidity struct {
		NotBefore time.Time `asn1:"generalized"`
		NotAfter  time.Time `asn1:"generalized"`
	}
	seq := roleValidity{NotBefore: nb, NotAfter: na}
	val, _ := asn1.Marshal(seq)
	return Attribute{
		AttrType:   OIDAtomRoleValidityPeriod,
		AttrValues: []asn1.RawValue{{FullBytes: val}},
	}
}

func marshalAuthenticatedAttributes(contentDigest []byte, attrs SignerAttrs) ([]byte, error) {
	// Собираем атрибуты: contentType, messageDigest, VIN, VER, UID; затем сортируем по DER (SET OF Attribute, X.690).
	contentTypeVal, _ := asn1.Marshal(OIDPKCS7Data)
	messageDigestVal, _ := asn1.Marshal(contentDigest)
	list := []Attribute{
		{AttrType: OIDPKCS9ContentType, AttrValues: []asn1.RawValue{{FullBytes: contentTypeVal}}},
	}
	if attrs.VIN != "" {
		list = append(list, attrUTF8String(OIDAtomVIN, attrs.VIN))
	}
	if !attrs.VERTimestamp.IsZero() || attrs.VERVersion != 0 {
		verSeq, _ := asn1.Marshal(struct {
			Ts time.Time `asn1:"generalized"`
			V  int
		}{Ts: attrs.VERTimestamp.UTC(), V: attrs.VERVersion})
		list = append(list, Attribute{
			AttrType:   OIDAtomVER,
			AttrValues: []asn1.RawValue{{FullBytes: verSeq}},
		})
	}
	if attrs.UID != "" {
		list = append(list, attrUTF8String(OIDAtomUID, attrs.UID))
	}
	list = append(list, Attribute{AttrType: OIDPKCS9MessageDigest, AttrValues: []asn1.RawValue{{FullBytes: messageDigestVal}}})
	list = sortAttributesByDER(list)
	return marshalAttributeSet(list)
}

func sortAttributesByDER(attrs []Attribute) []Attribute {
	if len(attrs) <= 1 {
		return attrs
	}
	type withDER struct {
		der []byte
		a   Attribute
	}
	list := make([]withDER, 0, len(attrs))
	for _, a := range attrs {
		enc, err := asn1.Marshal(a)
		if err != nil {
			return attrs
		}
		list = append(list, withDER{der: enc, a: a})
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].der, list[j].der) < 0 })
	out := make([]Attribute, len(list))
	for i := range list {
		out[i] = list[i].a
	}
	return out
}

func marshalAttributeSet(attrs []Attribute) ([]byte, error) {
	var setBytes []byte
	for _, a := range attrs {
		enc, err := asn1.Marshal(a)
		if err != nil {
			return nil, err
		}
		setBytes = append(setBytes, enc...)
	}
	l := len(setBytes)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l < 256 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{0x31}, lenBytes...), setBytes...), nil
}

// marshalSubjectKeyIdentifier кодирует SID как [0] EXPLICIT OCTET STRING (эталон demo-original-container).
// Итог: тег 0xA0 (context 0, constructed) + длина + (OCTET STRING 0x04 + длина + SKID).
func marshalSubjectKeyIdentifier(ski []byte) ([]byte, error) {
	if len(ski) == 0 {
		return nil, fmt.Errorf("subjectKeyIdentifier required")
	}
	octetDER, err := asn1.Marshal(ski)
	if err != nil {
		return nil, err
	}
	// [0] EXPLICIT: 0xA0 + длина + OCTET STRING TLV
	l := len(octetDER)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l < 256 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{0xA0}, lenBytes...), octetDER...), nil
}

func signAuthenticatedAttributes(key *ecdsa.PrivateKey, authAttrsDER []byte) ([]byte, error) {
	hash := sha256.Sum256(authAttrsDER)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, err
	}
	// ECDSA signature в CMS — DER SEQUENCE { r INTEGER, s INTEGER }
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

// marshalCertificateSet кодирует SET OF Certificate (каждый Certificate — OCTET STRING).
// Элементы сортируются по DER (X.690); длина — минимальное число байт.
func marshalCertificateSet(certs [][]byte) ([]byte, error) {
	if len(certs) == 0 {
		return []byte{0x31, 0x00}, nil
	}
	type withDER struct {
		der []byte
		raw []byte
	}
	list := make([]withDER, 0, len(certs))
	for _, raw := range certs {
		octet, err := asn1.Marshal(raw)
		if err != nil {
			return nil, err
		}
		list = append(list, withDER{der: octet, raw: raw})
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].der, list[j].der) < 0 })
	var setBytes []byte
	for _, e := range list {
		setBytes = append(setBytes, e.der...)
	}
	l := len(setBytes)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else if l < 256 {
		lenBytes = []byte{0x81, byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{0x31}, lenBytes...), setBytes...), nil
}
