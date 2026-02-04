package registry

import "encoding/asn1"

// Константы OID из registry.asn1: PKCS#7, PKCS#9, типы сертификатов PKCS#12 и атрибуты ATOM.
var (
	OIDPKCS7SignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDPKCS7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDPKCS9ContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDPKCS9MessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDPKCS9LocalKeyID    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	OIDPKCS9FriendlyName  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	// Типы мешков сертификатов PKCS#12
	OIDX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	OIDSdsiCertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}
	OIDCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}

	// Атрибуты ATOM (1.3.6.1.4.1.99999.1.x): VIN, версия, UID, роль, период действия роли
	OIDAtomVIN                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	OIDAtomVER                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 2}
	OIDAtomUID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 3}
	OIDAtomRoleName           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 4}
	OIDAtomRoleValidityPeriod = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 5}
)

// AtomOIDs — список всех OID атрибутов ATOM для поиска и итерации.
var AtomOIDs = []asn1.ObjectIdentifier{
	OIDAtomVIN, OIDAtomVER, OIDAtomUID, OIDAtomRoleName, OIDAtomRoleValidityPeriod,
}

// OIDToAtomName возвращает читаемое имя для OID атрибута (VIN, UID, roleName и т.д.) или пустую строку.
func OIDToAtomName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDAtomVIN):
		return "VIN"
	case oid.Equal(OIDAtomVER):
		return "VER"
	case oid.Equal(OIDAtomUID):
		return "UID"
	case oid.Equal(OIDAtomRoleName):
		return "roleName"
	case oid.Equal(OIDAtomRoleValidityPeriod):
		return "roleValidityPeriod"
	case oid.Equal(OIDPKCS9ContentType):
		return "contentType"
	case oid.Equal(OIDPKCS9MessageDigest):
		return "messageDigest"
	case oid.Equal(OIDPKCS9LocalKeyID):
		return "localKeyID"
	case oid.Equal(OIDPKCS9FriendlyName):
		return "friendlyName"
	case oid.Equal(OIDX509Certificate):
		return "x509Certificate"
	case oid.Equal(OIDSdsiCertificate):
		return "sdsiCertificate"
	case oid.Equal(OIDCertBag):
		return "certBag"
	default:
		return ""
	}
}

// CertTypeName возвращает краткое описание типа сертификата по OID (например, «X.509 Certificate»).
func CertTypeName(oid asn1.ObjectIdentifier) string {
	if oid.Equal(OIDX509Certificate) {
		return "X.509 Certificate"
	}
	if oid.Equal(OIDSdsiCertificate) {
		return "SDSI Certificate"
	}
	if n := OIDToAtomName(oid); n != "" {
		return n
	}
	return oid.String()
}
