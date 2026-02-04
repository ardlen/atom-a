package registry

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

// SafeBagInput — входные данные для одного SafeBag: сертификат и атрибуты мешка.
type SafeBagInput struct {
	CertDER         []byte // DER сертификата X.509
	RoleName        string
	RoleNotBefore   time.Time
	RoleNotAfter    time.Time
	LocalKeyID      []byte // обычно SubjectKeyId или произвольный идентификатор
}

// SignerAttrs — атрибуты подписанта для authenticatedAttributes (VIN, VER, UID).
type SignerAttrs struct {
	VIN           string
	VERTimestamp  time.Time
	VERVersion    int
	UID           string
}

// BuildRegistry собирает реестр ATOM-PKCS12-REGISTRY: PFX с authSafe = ContentInfo(SignedData).
// signerCert — сертификат подписанта, signerKey — приватный ключ для подписи.
// safeBags — список мешков (сертификаты + атрибуты для eContent).
// Возвращает DER-кодированный PFX.
func BuildRegistry(signerCert *x509.Certificate, signerKey *ecdsa.PrivateKey, safeBags []SafeBagInput, attrs SignerAttrs) ([]byte, error) {
	if signerCert == nil || signerKey == nil {
		return nil, fmt.Errorf("signer cert and key required")
	}

	// 1. Собрать SafeContents (SEQUENCE OF SafeBag)
	safeContentsDER, err := marshalSafeContents(safeBags)
	if err != nil {
		return nil, fmt.Errorf("marshal SafeContents: %w", err)
	}

	// 2. encapContentInfo: eContentType = pkcs7-data, eContent = [0] EXPLICIT OCTET STRING(safeContentsDER)
	encapContentInfo := EncapsulatedContentInfo{
		EContentType: OIDPKCS7Data,
		EContent:     safeContentsDER, // asn1 закодирует как [0] EXPLICIT OCTET STRING
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

	authAttrsRaw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: authAttrsDER, IsCompound: true}
	signerInfo := SignerInfo{
		Version:                   1,
		SID:                       asn1.RawValue{FullBytes: sidDER},
		DigestAlgorithm:           AlgorithmIdentifier{Algorithm: OIDSHA256},
		AuthenticatedAttributes:   authAttrsRaw,
		DigestEncryptionAlgorithm: AlgorithmIdentifier{Algorithm: OIDECDSAWithSHA256},
		EncryptedDigest:           sigDER,
	}

	signedData := SignedData{
		Version:          1,
		DigestAlgorithms: []AlgorithmIdentifier{{Algorithm: OIDSHA256}},
		EncapContentInfo: encapContentInfo,
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: certSetDER, IsCompound: true},
		SignerInfos:      []SignerInfo{signerInfo},
	}

	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}

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
	OIDSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDECDSAWithSHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

func marshalSafeContents(inputs []SafeBagInput) ([]byte, error) {
	var bags []SafeBag
	for _, in := range inputs {
		cb := CertBag{
			CertId:    OIDX509Certificate,
			CertValue: in.CertDER,
		}
		cbDER, err := asn1.Marshal(cb)
		if err != nil {
			return nil, err
		}
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
		if len(in.LocalKeyID) > 0 {
			bagAttrs = append(bagAttrs, attrOctetString(OIDPKCS9LocalKeyID, in.LocalKeyID))
		}

		bags = append(bags, SafeBag{
			BagId:         OIDCertBag,
			BagValue:      bagValue,
			BagAttributes: bagAttrs,
		})
	}
	return asn1.Marshal(SafeContents(bags))
}

func attrUTF8String(oid asn1.ObjectIdentifier, s string) Attribute {
	val, _ := asn1.Marshal(s)
	return Attribute{AttrType: oid, AttrValues: []asn1.RawValue{{FullBytes: val}}}
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
	// Порядок атрибутов: contentType, messageDigest, VIN, VER, UID (как в эталоне).
	// Значения атрибутов — полный DER (OID, OCTET STRING и т.д.) через FullBytes.
	contentTypeVal, _ := asn1.Marshal(OIDPKCS7Data)
	messageDigestVal, _ := asn1.Marshal(contentDigest)
	list := []Attribute{
		{AttrType: OIDPKCS9ContentType, AttrValues: []asn1.RawValue{{FullBytes: contentTypeVal}}},
		{AttrType: OIDPKCS9MessageDigest, AttrValues: []asn1.RawValue{{FullBytes: messageDigestVal}}},
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

	return asn1.Marshal(list)
}

func marshalSubjectKeyIdentifier(ski []byte) ([]byte, error) {
	if len(ski) == 0 {
		return nil, fmt.Errorf("subjectKeyIdentifier required")
	}
	octet, _ := asn1.Marshal(ski)
	return asn1.MarshalWithParams(octet, "explicit,tag:0")
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
func marshalCertificateSet(certs [][]byte) ([]byte, error) {
	var setBytes []byte
	for _, raw := range certs {
		octet, err := asn1.Marshal(raw)
		if err != nil {
			return nil, err
		}
		setBytes = append(setBytes, octet...)
	}
	// SET tag = 0x31, затем DER-длина
	l := len(setBytes)
	var lenBytes []byte
	if l < 128 {
		lenBytes = []byte{byte(l)}
	} else {
		lenBytes = []byte{0x82, byte(l >> 8), byte(l)}
	}
	return append(append([]byte{0x31}, lenBytes...), setBytes...), nil
}
