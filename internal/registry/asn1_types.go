package registry

import "encoding/asn1"

// PFX — верхний уровень контейнера PKCS#12 (registry.asn1).
// SEQUENCE { version(3), authSafe ContentInfo, macData? }.
type PFX struct {
	Version  int
	AuthSafe ContentInfo
	MacData  *MacData `asn1:"optional"`
}

// ContentInfo — обёртка содержимого CMS (registry.asn1).
// В ATOM-PKCS12-REGISTRY authSafe содержит один ContentInfo с contentType = pkcs7-signedData.
// content [0] IMPLICIT SignedData (DEFINITIONS IMPLICIT TAGS).
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

// MacData — данные целостности PKCS#12 (опционально; в текущих контейнерах может отсутствовать).
type MacData struct {
	Mac        DigestInfo
	MacSalt    []byte
	Iterations int `asn1:"default:1"`
}

// DigestInfo — алгоритм хеширования и значение хеша.
type DigestInfo struct {
	DigestAlgorithm AlgorithmIdentifier
	Digest          []byte
}

// SignedData — структура CMS SignedData (registry.asn1).
// Содержит алгоритмы хеширования, запечатанный контент (eContent), сертификаты и подписи.
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT CertificateSet
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// AlgorithmIdentifier — идентификатор алгоритма и опциональные параметры (ASN.1).
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// EncapsulatedContentInfo — тип и значение запечатанного контента (pkcs7-data, OCTET STRING = SafeContents).
// eContent [0] IMPLICIT OCTET STRING — примитивный тег 0x80, значение без вложенного 04.
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,tag:0"`
}

// SignerInfo — информация о подписанте CMS: идентификатор, алгоритмы, атрибуты, подпись.
// SignerIdentifier (SID) — CHOICE: subjectKeyIdentifier [0] или issuerAndSerialNumber.
type SignerInfo struct {
	Version                   int
	SID                       asn1.RawValue // SignerIdentifier (CHOICE)
	DigestAlgorithm           AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"` // [0] IMPLICIT Attributes
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

// SafeContents — последовательность мешков SafeBag (PKCS#12), хранящаяся в eContent.
type SafeContents []SafeBag

// SafeBag — один мешок PKCS#12: идентификатор типа, значение (CertBag) и опциональные атрибуты.
// bagValue [0] IMPLICIT CertBag.
type SafeBag struct {
	BagId         asn1.ObjectIdentifier
	BagValue      asn1.RawValue `asn1:"tag:0"`
	BagAttributes []Attribute   `asn1:"optional,set"`
}

// CertBag — содержимое мешка сертификата: тип (certId) и значение (DER сертификата).
// certValue [0] IMPLICIT OCTET STRING — примитивный 0x80, значение без 04.
type CertBag struct {
	CertId    asn1.ObjectIdentifier
	CertValue asn1.RawValue `asn1:"tag:0"`
}

// Attribute — один атрибут: OID типа и набор значений (SET OF).
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues []asn1.RawValue `asn1:"set"`
}

// VER (ATOM) — версия: SEQUENCE { GeneralizedTime, INTEGER } (timestamp и номер версии).
type VER struct {
	Timestamp     string
	VersionNumber int
}

// RoleValidityPeriod (ATOM) — период действия роли: notBeforeTime и notAfterTime (GeneralizedTime).
type RoleValidityPeriod struct {
	NotBefore string
	NotAfter  string
}
