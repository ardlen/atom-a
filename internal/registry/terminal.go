// terminal.go — ANSI-цвета, иконки, SignerCert (поиск сертификата подписанта по SubjectKeyIdentifier).
package registry

import (
	"encoding/asn1"

	"crypto/x509"
)

// ANSI-коды для оформления вывода в терминале (используются только при выводе в TTY; вызывающий код может отключить).
var (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Cyan    = "\033[36m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Magenta = "\033[35m"
	Blue    = "\033[34m"
)

// Иконки для секций отчёта (Unicode).
const (
	IconPFX        = "📦"
	IconCert       = "📜"
	IconSigner     = "🔐"
	IconSafeBag    = "📋"
	IconSignerInfo = "✍️"
	IconKey        = "🔑"
	IconTime       = "📅"
	IconId         = "🆔"
)

// SignerCert возвращает сертификат подписанта для данного SignerInfo, или nil если не найден.
// SID в SignerInfo — [0] subjectKeyIdentifier (OCTET STRING). Поиск в c.Certificates по совпадению SubjectKeyId.
// Поддерживается как сырое значение OCTET STRING в si.SID.Bytes, так и DER-обёртка (04 ll val).
func (c *Container) SignerCert(si *SignerInfo) *x509.Certificate {
	raw := si.SID
	if len(raw.Bytes) == 0 {
		return nil
	}
	// Контекстный тег 0 — subjectKeyIdentifier; содержимое может быть сырым значением OCTET STRING или DER-кодировкой.
	var ski []byte
	if raw.Tag == 0 {
		ski = raw.Bytes
		// Если Bytes — DER OCTET STRING (04 len val), разбираем и берём значение.
		if len(ski) > 0 && ski[0] == 0x04 {
			var octet []byte
			if _, err := asn1.Unmarshal(ski, &octet); err == nil {
				ski = octet
			}
		}
		for _, cert := range c.Certificates {
			if len(cert.SubjectKeyId) == len(ski) && bytesEqual(cert.SubjectKeyId, ski) {
				return cert
			}
		}
	}
	return nil
}

// bytesEqual сравнивает два среза байт побайтово.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
