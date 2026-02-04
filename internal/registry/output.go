package registry

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// hexEncode кодирует байты в hex-строку для вывода (например, SubjectKeyId).
func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// sanitizeExportBasename заменяет недопустимые в имени файла символы на подчёркивание и обрезает длину.
func sanitizeExportBasename(s string) string {
	const maxLen = 64
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
	s = re.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// CertExportBasename возвращает базовое имя файла (без .pem) для выгрузки сертификата из SignedData.
// Для сертификата подписанта используется атрибут roleName из SignerInfo; для остальных — "cert-N".
func (c *Container) CertExportBasename(cert *x509.Certificate, index int) string {
	for i := range c.Signers {
		if c.SignerCert(&c.Signers[i]) == cert {
			roleName := SignerRoleName(&c.Signers[i])
			if roleName != "" {
				s := sanitizeExportBasename(roleName)
				if s != "" {
					return s
				}
			}
			break
		}
	}
	return fmt.Sprintf("cert-%d", index+1)
}

// SafeBagRoleName возвращает значение атрибута roleName из BagAttributes мешка.
func SafeBagRoleName(info *SafeBagInfo) string {
	for _, a := range info.BagAttributes {
		if a.Name == "roleName" && a.Value != "" {
			return a.Value
		}
	}
	return ""
}

// SafeBagExportBasename возвращает базовое имя файла (без .pem) для выгрузки сертификата из SafeBag:
// roleName_Serial (из атрибутов мешка и CertSummary). При отсутствии roleName — cert_Serial или cert-N.
func SafeBagExportBasename(info *SafeBagInfo, index int) string {
	roleName := SafeBagRoleName(info)
	serial := ""
	if info.CertSummary != nil {
		serial = strings.TrimSpace(info.CertSummary.Serial)
	}
	sRole := sanitizeExportBasename(roleName)
	sSerial := sanitizeExportBasename(serial)
	if sRole != "" && sSerial != "" {
		return sRole + "_" + sSerial
	}
	if sRole != "" {
		return sRole
	}
	if sSerial != "" {
		return "cert_" + sSerial
	}
	return fmt.Sprintf("cert-%d", index+1)
}

// Форматы вывода для CLI.
const (
	FormatText             = "text"
	FormatJSON             = "json"
	FormatJSONCertificates = "json-certificates" // только реальные данные сертификатов в JSON
	FormatPEM              = "pem"               // все сертификаты в PEM для криптоопераций
)

// TextOutput формирует человекочитаемый отчёт и записывает его в strings.Builder.
// При useColor=true используются ANSI-цвета и иконки для удобства чтения; при -no-color — только текст и reset в начале.
func (c *Container) TextOutput(sb *strings.Builder, useColor bool) {
	bold, dim, val, head, certHead, nameColor, reset := "", "", "", "", "", "", ""
	if useColor {
		bold, dim, val, head, certHead, nameColor, reset = Bold, Dim, Cyan, Bold+Yellow, Bold+Green, Magenta, Reset
		sb.WriteString(head + IconPFX + " PFX" + reset + "\n")
	} else {
		reset = Reset
		sb.WriteString(reset)
		sb.WriteString("=== PFX ===\n")
	}
	sb.WriteString(fmt.Sprintf("  %sVersion:%s    %s%d%s\n", dim, reset, val, c.PFXVersion, reset))
	sb.WriteString(fmt.Sprintf("  %sContentType:%s %s%s%s\n", dim, reset, val, c.ContentType, reset))

	// Секция: сертификаты из SignedData (subject, issuer, serial, срок действия, KeyAlg, SubjectKeyId).
	if useColor {
		sb.WriteString("\n" + head + IconCert + " Certificates" + reset + "\n")
	} else {
		sb.WriteString("\n=== Certificates ===\n")
	}
	for i, cert := range c.Certificates {
		isSigner := c.isSignerCert(cert)
		mark := ""
		if useColor && isSigner {
			mark = " " + IconSigner + " " + Bold + Green + "(подписант контейнера)" + reset
		}
		if useColor {
			sb.WriteString(fmt.Sprintf("  %s[%d]%s %sSubject:%s %s%s%s\n", bold, i+1, reset, dim, reset, certHead, cert.Subject.String(), reset))
		} else {
			sb.WriteString(fmt.Sprintf("  [%d] Subject: %s%s\n", i+1, cert.Subject.String(), mark))
		}
		sb.WriteString(fmt.Sprintf("       %sIssuer:%s   %s%s\n", dim, reset, val, cert.Issuer.String()))
		sb.WriteString(fmt.Sprintf("       %sSerial:%s   %s%s\n", dim, reset, val, cert.SerialNumber.Text(16)))
		sb.WriteString(fmt.Sprintf("       %sValid:%s    %s%s — %s\n", dim, reset, val, cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("       %sKeyAlg:%s   %s%s\n", dim, reset, val, cert.PublicKeyAlgorithm.String()))
		if len(cert.SubjectKeyId) > 0 {
			sb.WriteString(fmt.Sprintf("       %sSubjectKeyId:%s %s%x\n", dim, reset, val, cert.SubjectKeyId))
		}
		if !useColor && isSigner {
			sb.WriteString("       (подписант контейнера)\n")
		}
		sb.WriteString(reset)
	}

	// Секция: подписант контейнера — кто подписал SignedData (Subject, Serial, KeyAlg по сертификату из SID).
	if len(c.Signers) > 0 {
		if useColor {
			sb.WriteString("\n" + head + IconSigner + " Подписант контейнера" + reset + "\n")
		} else {
			sb.WriteString("\n=== Подписант контейнера ===\n")
		}
		for i, si := range c.Signers {
			signerCert := c.SignerCert(&si)
			if signerCert != nil {
				if useColor {
					sb.WriteString(fmt.Sprintf("  %s%s%s\n", bold, signerCert.Subject.String(), reset))
					sb.WriteString(fmt.Sprintf("    %sSerial:%s %s%s  %sKeyAlg:%s %s%s\n", dim, reset, val, signerCert.SerialNumber.Text(16), dim, reset, val, signerCert.PublicKeyAlgorithm.String()))
				} else {
					sb.WriteString(fmt.Sprintf("  Subject: %s\n", signerCert.Subject.String()))
					sb.WriteString(fmt.Sprintf("  Serial:  %s\n", signerCert.SerialNumber.Text(16)))
					sb.WriteString(fmt.Sprintf("  KeyAlg:  %s\n", signerCert.PublicKeyAlgorithm.String()))
				}
			} else {
				sb.WriteString(fmt.Sprintf("  Signer [%d] (сертификат не найден в списке)\n", i+1))
			}
		}
	}

	// Секция: SafeContents (eContent) — мешки SafeBag с certId, данными сертификата и атрибутами мешка.
	if len(c.SafeBagInfos) > 0 {
		if useColor {
			sb.WriteString("\n" + head + IconSafeBag + " SafeContents (eContent)" + reset + "\n")
		} else {
			sb.WriteString("\n=== SafeContents (eContent) ===\n")
		}
		for i, info := range c.SafeBagInfos {
			if useColor {
				sb.WriteString(fmt.Sprintf("  %s[%d]%s %sbagId:%s %s%s\n", bold, i+1, reset, dim, reset, val, info.BagId))
			} else {
				sb.WriteString(fmt.Sprintf("  [%d] bagId: %s\n", i+1, info.BagId))
			}
			sb.WriteString(fmt.Sprintf("       %scertId:%s   %s%s%s (%s)\n", dim, reset, val, info.CertId, reset, info.CertType))
			if info.CertSummary != nil {
				sb.WriteString(fmt.Sprintf("       %sSubject:%s  %s%s\n", dim, reset, val, info.CertSummary.Subject))
				sb.WriteString(fmt.Sprintf("       %sIssuer:%s   %s%s\n", dim, reset, val, info.CertSummary.Issuer))
				sb.WriteString(fmt.Sprintf("       %sSerial:%s   %s%s\n", dim, reset, val, info.CertSummary.Serial))
				sb.WriteString(fmt.Sprintf("       %sValid:%s    %s%s — %s\n", dim, reset, val, info.CertSummary.NotBefore, info.CertSummary.NotAfter))
				sb.WriteString(fmt.Sprintf("       %sKeyAlg:%s   %s%s\n", dim, reset, val, info.CertSummary.KeyAlg))
			} else {
				sb.WriteString(fmt.Sprintf("       %scertValue:%s %s%d bytes (not X.509)\n", dim, reset, val, info.CertValueLen))
			}
			for _, attr := range info.BagAttributes {
				sb.WriteString(fmt.Sprintf("       %s%s:%s %s%s\n", nameColor, attr.Name, reset, val, attr.Value))
			}
			sb.WriteString(reset)
		}
	}

	// Секция: подписанты и ATOM-атрибуты (алгоритмы подписи и расшифрованные атрибуты: VIN, VER, UID и т.д.).
	if useColor {
		sb.WriteString("\n" + head + IconSignerInfo + " Signers and ATOM attributes" + reset + "\n")
	} else {
		sb.WriteString("\n=== Signers and ATOM attributes ===\n")
	}
	for i, si := range c.Signers {
		sb.WriteString(fmt.Sprintf("  %sSigner [%d]%s\n", bold, i+1, reset))
		sb.WriteString(fmt.Sprintf("    %sDigestAlgorithm:%s %s%s\n", dim, reset, val, si.DigestAlgorithm.Algorithm))
		sb.WriteString(fmt.Sprintf("    %sSignatureAlgorithm:%s %s%s\n", dim, reset, val, si.DigestEncryptionAlgorithm.Algorithm))
		attrs, err := SignerAttributes(&si)
		if err != nil {
			sb.WriteString(fmt.Sprintf("    (attributes parse error: %v)\n", err))
			continue
		}
		for _, a := range attrs {
			vals := DecodeAttributeValues(a)
			for _, v := range vals {
				disp := v.Value
				if disp == "" {
					disp = v.Raw
				}
				if disp != "" {
					sb.WriteString(fmt.Sprintf("    %s%s:%s %s%s\n", nameColor, v.Name, reset, val, disp))
				}
			}
		}
		sb.WriteString(reset)
	}
}

// isSignerCert возвращает true, если сертификат cert используется подписантом контейнера (совпадает с SID любого SignerInfo).
func (c *Container) isSignerCert(cert *x509.Certificate) bool {
	for i := range c.Signers {
		if c.SignerCert(&c.Signers[i]) == cert {
			return true
		}
	}
	return false
}

// certToJSONMap формирует полную JSON-структуру реальных данных сертификата (subject, issuer, serial, сроки, алгоритмы, расширения, SAN, raw DER).
func certToJSONMap(cert *x509.Certificate, isSigner bool) map[string]interface{} {
	m := map[string]interface{}{
		"subject":             cert.Subject.String(),
		"issuer":              cert.Issuer.String(),
		"serialNumber":        cert.SerialNumber.String(),
		"serialNumberHex":     cert.SerialNumber.Text(16),
		"notBefore":           cert.NotBefore.Format("2006-01-02T15:04:05Z07:00"),
		"notAfter":            cert.NotAfter.Format("2006-01-02T15:04:05Z07:00"),
		"version":             cert.Version,
		"signatureAlgorithm":  cert.SignatureAlgorithm.String(),
		"publicKeyAlgorithm":  cert.PublicKeyAlgorithm.String(),
		"isSigner":            isSigner,
	}
	if len(cert.SubjectKeyId) > 0 {
		m["subjectKeyId"] = hexEncode(cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) > 0 {
		m["authorityKeyId"] = hexEncode(cert.AuthorityKeyId)
	}
	if cert.KeyUsage != 0 {
		m["keyUsage"] = keyUsageStrings(cert.KeyUsage)
	}
	if len(cert.ExtKeyUsage) > 0 {
		m["extKeyUsage"] = extKeyUsageStrings(cert.ExtKeyUsage)
	}
	if len(cert.DNSNames) > 0 {
		m["dnsNames"] = cert.DNSNames
	}
	if len(cert.EmailAddresses) > 0 {
		m["emailAddresses"] = cert.EmailAddresses
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, 0, len(cert.IPAddresses))
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		m["ipAddresses"] = ips
	}
	if len(cert.URIs) > 0 {
		uris := make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			uris = append(uris, u.String())
		}
		m["uris"] = uris
	}
	if len(cert.Raw) > 0 {
		m["raw"] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return m
}

// keyUsageStrings возвращает человекочитаемые имена битов KeyUsage (для выгрузки в JSON).
func keyUsageStrings(ku x509.KeyUsage) []string {
	var s []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		s = append(s, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		s = append(s, "contentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		s = append(s, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		s = append(s, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		s = append(s, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		s = append(s, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		s = append(s, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		s = append(s, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		s = append(s, "decipherOnly")
	}
	return s
}

// extKeyUsageStrings возвращает строковое представление ExtKeyUsage для JSON.
func extKeyUsageStrings(eku []x509.ExtKeyUsage) []string {
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                    "any",
		x509.ExtKeyUsageServerAuth:             "serverAuth",
		x509.ExtKeyUsageClientAuth:             "clientAuth",
		x509.ExtKeyUsageCodeSigning:            "codeSigning",
		x509.ExtKeyUsageEmailProtection:        "emailProtection",
		x509.ExtKeyUsageIPSECEndSystem:         "ipsecEndSystem",
		x509.ExtKeyUsageIPSECTunnel:             "ipsecTunnel",
		x509.ExtKeyUsageIPSECUser:              "ipsecUser",
		x509.ExtKeyUsageTimeStamping:           "timeStamping",
		x509.ExtKeyUsageOCSPSigning:            "ocspSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "msSGC",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:   "nsSGC",
	}
	out := make([]string, 0, len(eku))
	for _, u := range eku {
		if n, ok := names[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", u))
		}
	}
	return out
}

// JSONOutput возвращает структуру, пригодную для json.Marshal (карта с ключами pfxVersion, certificates, safeBags, signers и т.д.).
// Сертификаты выгружаются в виде полных реальных данных (subject, issuer, serial, сроки, алгоритмы, расширения, SAN, raw DER в base64).
func (c *Container) JSONOutput() interface{} {
	type safeBagInfo struct {
		BagID         string              `json:"bagId"`
		CertID        string              `json:"certId"`
		CertType      string              `json:"certType"`
		CertSummary   *CertSummary        `json:"certSummary,omitempty"`
		CertValueLen  int                 `json:"certValueLen,omitempty"`
		BagAttributes []BagAttributeValue `json:"bagAttributes,omitempty"`
	}
	type attrOut struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type signerOut struct {
		DigestAlgorithm    string    `json:"digestAlgorithm"`
		SignatureAlgorithm string    `json:"signatureAlgorithm"`
		Attributes         []attrOut `json:"attributes"`
	}
	certs := make([]map[string]interface{}, 0, len(c.Certificates))
	for _, cert := range c.Certificates {
		certs = append(certs, certToJSONMap(cert, c.isSignerCert(cert)))
	}
	bags := make([]safeBagInfo, 0, len(c.SafeBagInfos))
	for _, info := range c.SafeBagInfos {
		bags = append(bags, safeBagInfo{
			BagID:         info.BagId.String(),
			CertID:        info.CertId.String(),
			CertType:      info.CertType,
			CertSummary:   info.CertSummary,
			CertValueLen:  info.CertValueLen,
			BagAttributes: info.BagAttributes,
		})
	}
	signers := make([]signerOut, 0, len(c.Signers))
	for _, si := range c.Signers {
		so := signerOut{
			DigestAlgorithm:    si.DigestAlgorithm.Algorithm.String(),
			SignatureAlgorithm: si.DigestEncryptionAlgorithm.Algorithm.String(),
			Attributes:         nil,
		}
		attrs, _ := SignerAttributes(&si)
		for _, a := range attrs {
			for _, v := range DecodeAttributeValues(a) {
				val := v.Value
				if val == "" {
					val = v.Raw
				}
				so.Attributes = append(so.Attributes, attrOut{Name: v.Name, Value: val})
			}
		}
		signers = append(signers, so)
	}
	return map[string]interface{}{
		"pfxVersion":   c.PFXVersion,
		"contentType":  c.ContentType.String(),
		"certificates": certs,
		"safeBags":     bags,
		"signers":      signers,
	}
}

// ToJSON возвращает отформатированные JSON-байты контейнера.
func (c *Container) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c.JSONOutput(), "", "  ")
}

// CertificatesJSONOutput возвращает структуру только с реальными данными сертификатов (subject, issuer, serial, сроки, алгоритмы, расширения, SAN, raw DER).
// Удобно для выгрузки в файл или потребления другими инструментами.
func (c *Container) CertificatesJSONOutput() interface{} {
	certs := make([]map[string]interface{}, 0, len(c.Certificates))
	for _, cert := range c.Certificates {
		certs = append(certs, certToJSONMap(cert, c.isSignerCert(cert)))
	}
	return map[string]interface{}{"certificates": certs}
}

// ToCertificatesJSON возвращает отформатированные JSON-байты только с массивом сертификатов.
func (c *Container) ToCertificatesJSON() ([]byte, error) {
	return json.MarshalIndent(c.CertificatesJSONOutput(), "", "  ")
}

// ToPEM возвращает все сертификаты из реестра в формате PEM (последовательность блоков
// -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----). Готово для загрузки в
// x509.CertPool, OpenSSL или другие криптобиблиотеки.
func (c *Container) ToPEM() ([]byte, error) {
	var b []byte
	for _, cert := range c.Certificates {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		b = append(b, pem.EncodeToMemory(block)...)
	}
	return b, nil
}

// ToSafeBagsPEM возвращает все сертификаты из SafeBags (eContent) в формате PEM —
// последовательность блоков -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----.
// Включаются только мешки с X.509 (CertValueDER задан). Готово для криптоопераций.
func (c *Container) ToSafeBagsPEM() ([]byte, error) {
	var b []byte
	for _, info := range c.SafeBagInfos {
		if len(info.CertValueDER) == 0 {
			continue
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: info.CertValueDER}
		b = append(b, pem.EncodeToMemory(block)...)
	}
	return b, nil
}

// SignerCertPEM возвращает PEM сертификата подписанта контейнера (первый SignerInfo).
// Если подписант не найден среди c.Certificates, возвращает nil, nil.
func (c *Container) SignerCertPEM() ([]byte, error) {
	if len(c.Signers) == 0 {
		return nil, nil
	}
	cert := c.SignerCert(&c.Signers[0])
	if cert == nil {
		return nil, nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

