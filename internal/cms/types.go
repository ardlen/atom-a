// Package cms разбирает контейнеры CMS/PKCS#7 (.p7): ContentInfo с SignedData, сертификаты и eContent (в т.ч. PEM).
package cms

import (
	"encoding/asn1"
	"crypto/x509"
)

// OID CMS (RFC 5652).
var (
	OIDPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDPKCS7Data       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// ContentInfo — обёртка CMS (RFC 5652). Один объект с contentType и content [0].
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0"`
}

// SignedData — тело CMS SignedData.
type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// AlgorithmIdentifier — OID алгоритма и опциональные параметры.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// EncapsulatedContentInfo — eContentType и eContent [0] (OCTET STRING).
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,tag:0"`
}

// SignerInfo — подписант CMS: SID, алгоритмы, подпись.
type SignerInfo struct {
	Version                   int
	SID                       asn1.RawValue
	DigestAlgorithm           AlgorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

// Container — результат разбора .p7: ContentInfo, SignedData, сертификаты из certificates и из eContent (PEM).
type Container struct {
	ContentType     asn1.ObjectIdentifier
	Version         int
	EContentType    asn1.ObjectIdentifier
	EContentSize    int
	EContentRaw     []byte
	Certificates    []*x509.Certificate   // из SignedData.certificates
	EContentCerts   []*x509.Certificate   // из eContent (PEM-блоки)
	SignerInfos     []SignerInfo
	SignerCert      *x509.Certificate     // найденный сертификат подписанта (из certificates или eContentCerts)
}
