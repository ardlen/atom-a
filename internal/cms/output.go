package cms

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ANSI-коды для цветного вывода в терминале.
var (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiCyan  = "\033[36m"
	ansiGreen = "\033[32m"
	ansiYellow = "\033[33m"
	ansiMagenta = "\033[35m"
)

// Иконки для секций отчёта (Unicode).
const (
	iconCMS   = "📦"
	iconSign  = "🔐"
	iconCert  = "📜"
	iconSigner = "✍️"
)

// CertInfo — данные одного сертификата для отчёта (text/JSON).
type CertInfo struct {
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	Serial        string `json:"serial"`
	NotBefore     string `json:"notBefore"`
	NotAfter      string `json:"notAfter"`
	KeyAlgorithm  string `json:"keyAlgorithm"`
	PEM           string `json:"pem,omitempty"`
}

// SignerInfoSummary — данные одного элемента signerInfos для отчёта.
type SignerInfoSummary struct {
	Version                   int    `json:"version"`
	SIDType                   string `json:"sidType"`                   // "subjectKeyIdentifier" | "issuerAndSerialNumber"
	SID                       string `json:"sid"`                       // hex или описание
	DigestAlgorithm           string `json:"digestAlgorithm"`
	DigestEncryptionAlgorithm string `json:"digestEncryptionAlgorithm"`
	EncryptedDigestLen        int    `json:"encryptedDigestLen"`
	SignerCertFound           bool   `json:"signerCertFound"`
}

// Report — полный отчёт для вывода (JSON или текст).
type Report struct {
	ContentType      string             `json:"contentType"`
	Version          int                `json:"version"`
	EContentType     string             `json:"eContentType"`
	EContentSize     int                `json:"eContentSize"`
	SignersCount     int                `json:"signersCount"`
	SignerInfos      []SignerInfoSummary `json:"signerInfos,omitempty"`
	Certificates     []CertInfo         `json:"certificates,omitempty"`
	EContentCerts    []CertInfo         `json:"eContentPEMCerts,omitempty"`
	SignerCert       *CertInfo          `json:"signerCert,omitempty"`
}

func certToInfo(c *x509.Certificate, includePEM bool) CertInfo {
	info := CertInfo{
		Subject:      c.Subject.String(),
		Issuer:       c.Issuer.String(),
		Serial:       c.SerialNumber.Text(16),
		NotBefore:    c.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:     c.NotAfter.Format("2006-01-02 15:04:05"),
		KeyAlgorithm: c.PublicKeyAlgorithm.String(),
	}
	if includePEM {
		info.PEM = CertToPEM(c)
	}
	return info
}

// CertToPEM возвращает PEM-блок сертификата (строка).
func CertToPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// BuildReport формирует Report из Container. includePEM добавляет поле pem в каждый сертификат.
func (c *Container) BuildReport(includePEM bool) Report {
	r := Report{
		ContentType:   c.ContentType.String(),
		Version:       c.Version,
		EContentType:  c.EContentType.String(),
		EContentSize:  c.EContentSize,
		SignersCount:  len(c.SignerInfos),
	}
	for i, si := range c.SignerInfos {
		r.SignerInfos = append(r.SignerInfos, signerInfoSummary(&si, c.SignerCert != nil && i == 0))
	}
	for _, cert := range c.Certificates {
		r.Certificates = append(r.Certificates, certToInfo(cert, includePEM))
	}
	for _, cert := range c.EContentCerts {
		r.EContentCerts = append(r.EContentCerts, certToInfo(cert, includePEM))
	}
	if c.SignerCert != nil {
		si := certToInfo(c.SignerCert, includePEM)
		r.SignerCert = &si
	}
	return r
}

// Известные OID алгоритмов для читаемого вывода.
var (
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

func algorithmName(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidSHA256):
		return "sha256"
	case oid.Equal(oidECDSAWithSHA256):
		return "ecdsa-with-sha256"
	default:
		return oid.String()
	}
}

func signerInfoSummary(si *SignerInfo, certFound bool) SignerInfoSummary {
	sidType, sidStr := formatSID(si.SID)
	return SignerInfoSummary{
		Version:                   si.Version,
		SIDType:                   sidType,
		SID:                       sidStr,
		DigestAlgorithm:           algorithmName(si.DigestAlgorithm.Algorithm),
		DigestEncryptionAlgorithm: algorithmName(si.DigestEncryptionAlgorithm.Algorithm),
		EncryptedDigestLen:        len(si.EncryptedDigest),
		SignerCertFound:           certFound,
	}
}

// maxSIDTextLen — в текстовом отчёте выводим только начало SID (hex).
const maxSIDTextLen = 40

func truncateHex(hexStr string, maxLen int) string {
	if maxLen <= 0 || len(hexStr) <= maxLen {
		return hexStr
	}
	return hexStr[:maxLen] + "..."
}

func formatSID(sid asn1.RawValue) (sidType string, sidStr string) {
	if len(sid.Bytes) == 0 {
		return "unknown", ""
	}
	// [0] IMPLICIT = subjectKeyIdentifier (OCTET STRING)
	if sid.Tag == 0 {
		return "subjectKeyIdentifier", hex.EncodeToString(sid.Bytes)
	}
	// Обычно тег 0x80 для [0]; содержимое может быть OCTET STRING
	if sid.Class == asn1.ClassContextSpecific && sid.Tag == 0 {
		return "subjectKeyIdentifier", hex.EncodeToString(sid.Bytes)
	}
	if len(sid.Bytes) > 0 && (sid.Bytes[0] == 0x04 || sid.Bytes[0] == 0x80) {
		var octet []byte
		if _, err := asn1.Unmarshal(sid.Bytes, &octet); err == nil {
			return "subjectKeyIdentifier", hex.EncodeToString(octet)
		}
	}
	return "issuerAndSerialNumber", hex.EncodeToString(sid.Bytes)
}

// ToJSON возвращает JSON отчёта (с PEM в сертификатах).
func (c *Container) ToJSON(pretty bool) ([]byte, error) {
	r := c.BuildReport(true)
	if pretty {
		return json.MarshalIndent(r, "", "  ")
	}
	return json.Marshal(r)
}

// ToText возвращает человекочитаемый текстовый отчёт. При useColor=true — ANSI-цвета и иконки секций.
func (c *Container) ToText(useColor bool) string {
	r := c.BuildReport(false)
	var b strings.Builder
	bold, dim, val, head, certHead, reset := "", "", "", "", "", ""
	if useColor {
		bold, dim, val = ansiBold, ansiDim, ansiCyan
		head = ansiBold + ansiYellow
		certHead = ansiBold + ansiGreen
		reset = ansiReset
	}

	// Секция: CMS / SignedData
	if useColor {
		b.WriteString(head + iconCMS + " CMS SignedData" + reset + "\n")
	} else {
		b.WriteString("=== CMS SignedData ===\n")
	}
	b.WriteString(fmt.Sprintf("  %sContentType:%s  %s%s%s\n", dim, reset, val, r.ContentType, reset))
	b.WriteString(fmt.Sprintf("  %sVersion:%s       %s%d%s\n", dim, reset, val, r.Version, reset))
	b.WriteString(fmt.Sprintf("  %seContentType:%s  %s%s%s\n", dim, reset, val, r.EContentType, reset))
	b.WriteString(fmt.Sprintf("  %seContentSize:%s  %s%d%s\n", dim, reset, val, r.EContentSize, reset))
	b.WriteString(fmt.Sprintf("  %sSignersCount:%s  %s%d%s\n", dim, reset, val, r.SignersCount, reset))

	// Секция: SignerInfo
	if len(r.SignerInfos) > 0 {
		if useColor {
			b.WriteString("\n" + head + iconSign + " SignerInfo" + reset + "\n")
		} else {
			b.WriteString("\n=== SignerInfo ===\n")
		}
		for i, s := range r.SignerInfos {
			indent := "    "
			b.WriteString(fmt.Sprintf("  %s[%d]%s\n", bold, i+1, reset))
			b.WriteString(fmt.Sprintf("%s%sversion:%s     %s%d%s\n", indent, dim, reset, val, s.Version, reset))
			b.WriteString(fmt.Sprintf("%s%ssidType:%s    %s%s%s\n", indent, dim, reset, val, s.SIDType, reset))
			b.WriteString(fmt.Sprintf("%s%ssid:%s        %s%s%s\n", indent, dim, reset, val, truncateHex(s.SID, maxSIDTextLen), reset))
			b.WriteString(fmt.Sprintf("%s%sdigest:%s     %s%s%s\n", indent, dim, reset, val, s.DigestAlgorithm, reset))
			b.WriteString(fmt.Sprintf("%s%ssignature:%s  %s%s%s\n", indent, dim, reset, val, s.DigestEncryptionAlgorithm, reset))
			b.WriteString(fmt.Sprintf("%s%ssigLen:%s     %s%d%s\n", indent, dim, reset, val, s.EncryptedDigestLen, reset))
			b.WriteString(fmt.Sprintf("%s%ssignerCert:%s %s%v%s\n", indent, dim, reset, val, s.SignerCertFound, reset))
		}
	}

	// Секция: Certificates (SignedData)
	if useColor {
		b.WriteString("\n" + head + iconCert + " Certificates (SignedData)" + reset + "\n")
	} else {
		b.WriteString("\n=== Certificates (SignedData) ===\n")
	}
	b.WriteString(fmt.Sprintf("  %s(%d записей)%s\n", dim, len(r.Certificates), reset))
	for i, ci := range r.Certificates {
		if useColor {
			b.WriteString(fmt.Sprintf("  %s[%d]%s %sSubject:%s %s%s%s\n", bold, i+1, reset, dim, reset, certHead, ci.Subject, reset))
		} else {
			b.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, ci.Subject))
		}
		b.WriteString(fmt.Sprintf("       %sIssuer:%s  %s%s%s\n", dim, reset, val, ci.Issuer, reset))
		b.WriteString(fmt.Sprintf("       %sSerial:%s %s%s  %sNotBefore:%s %s%s  %sNotAfter:%s %s%s  %s%s%s\n", dim, reset, val, ci.Serial, dim, reset, val, ci.NotBefore, dim, reset, val, ci.NotAfter, dim, ci.KeyAlgorithm, reset))
	}

	// Секция: eContentPEMCerts
	if useColor {
		b.WriteString("\n" + head + iconCert + " eContentPEMCerts" + reset + "\n")
	} else {
		b.WriteString("\n=== eContentPEMCerts ===\n")
	}
	b.WriteString(fmt.Sprintf("  %s(%d записей)%s\n", dim, len(r.EContentCerts), reset))
	for i, ci := range r.EContentCerts {
		if useColor {
			b.WriteString(fmt.Sprintf("  %s[%d]%s %sSubject:%s %s%s%s\n", bold, i+1, reset, dim, reset, certHead, ci.Subject, reset))
		} else {
			b.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, ci.Subject))
		}
		b.WriteString(fmt.Sprintf("       %sIssuer:%s  %s%s%s\n", dim, reset, val, ci.Issuer, reset))
		b.WriteString(fmt.Sprintf("       %sSerial:%s %s%s  %sNotBefore:%s %s%s  %sNotAfter:%s %s%s  %s%s%s\n", dim, reset, val, ci.Serial, dim, reset, val, ci.NotBefore, dim, reset, val, ci.NotAfter, dim, ci.KeyAlgorithm, reset))
	}

	// Секция: SignerCert (если найден)
	if r.SignerCert != nil {
		if useColor {
			b.WriteString("\n" + head + iconSigner + " SignerCert" + reset + "\n")
		} else {
			b.WriteString("\n=== SignerCert ===\n")
		}
		sc := r.SignerCert
		if useColor {
			b.WriteString(fmt.Sprintf("  %s%s%s\n", certHead, sc.Subject, reset))
		} else {
			b.WriteString(fmt.Sprintf("  %s\n", sc.Subject))
		}
		b.WriteString(fmt.Sprintf("  %sIssuer:%s %s%s  %sSerial:%s %s%s  %s%s%s — %s%s  %s%s%s\n", dim, reset, val, sc.Issuer, dim, reset, val, sc.Serial, dim, val, sc.NotBefore, val, sc.NotAfter, dim, sc.KeyAlgorithm, reset))
	}
	return b.String()
}

// ExportCertsToDir записывает каждый сертификат из SignedData.certificates в dir (cert-1.pem, cert-2.pem, ...).
func (c *Container) ExportCertsToDir(dir string) (int, error) {
	for i, cert := range c.Certificates {
		name := fmt.Sprintf("cert-%d.pem", i+1)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(CertToPEM(cert)), 0644); err != nil {
			return i, err
		}
	}
	return len(c.Certificates), nil
}

// ExportEContentCertsToDir записывает каждый сертификат из eContent в dir (econtent-1.pem, ...).
func (c *Container) ExportEContentCertsToDir(dir string) (int, error) {
	for i, cert := range c.EContentCerts {
		name := fmt.Sprintf("econtent-%d.pem", i+1)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(CertToPEM(cert)), 0644); err != nil {
			return i, err
		}
	}
	return len(c.EContentCerts), nil
}

// ExportSignerCert записывает сертификат подписанта в файл outPath.
func (c *Container) ExportSignerCert(outPath string) error {
	if c.SignerCert == nil {
		return fmt.Errorf("signer cert not found")
	}
	return os.WriteFile(outPath, []byte(CertToPEM(c.SignerCert)), 0644)
}

// ToAllCertsPEM возвращает один PEM-файл со всеми сертификатами (SignedData.certificates + eContent PEM).
func (c *Container) ToAllCertsPEM() []byte {
	var b strings.Builder
	for _, cert := range c.Certificates {
		b.WriteString(CertToPEM(cert))
	}
	for _, cert := range c.EContentCerts {
		b.WriteString(CertToPEM(cert))
	}
	return []byte(b.String())
}
