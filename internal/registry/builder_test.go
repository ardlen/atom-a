package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestBuildRegistry проверяет, что собранный реестр успешно разбирается Parse().
func TestBuildRegistry(t *testing.T) {
	// Генерируем подписанта: ключ + самоподписанный сертификат.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ski := sha1.Sum(pubBytes)
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "Test Registry Signer"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski[:],
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Один SafeBag с тем же сертификатом (для простоты).
	verTime := time.Now().UTC().Truncate(time.Second)
	attrs := SignerAttrs{
		VIN:           "TESTVIN123",
		VERTimestamp:  verTime,
		VERVersion:    1,
		UID:           "CN=Test",
	}
	safeBags := []SafeBagInput{
		{
			CertDER:       certDER,
			RoleName:      "delegate",
			RoleNotBefore: verTime,
			RoleNotAfter:  verTime.Add(365 * 24 * time.Hour),
			LocalKeyID:    cert.SubjectKeyId,
		},
	}

	der, err := BuildRegistry(cert, key, safeBags, attrs)
	if err != nil {
		t.Fatalf("BuildRegistry: %v", err)
	}

	c, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse(built): %v", err)
	}
	if c.PFXVersion != 3 {
		t.Errorf("PFX version = %d", c.PFXVersion)
	}
	if !c.ContentType.Equal(OIDPKCS7SignedData) {
		t.Errorf("contentType = %v", c.ContentType)
	}
	if len(c.Certificates) != 1 {
		t.Errorf("certificates count = %d", len(c.Certificates))
	}
	if len(c.Signers) != 1 {
		t.Errorf("signers count = %d", len(c.Signers))
	}
	if len(c.SafeBagInfos) != 1 {
		t.Errorf("safeBagInfos count = %d", len(c.SafeBagInfos))
	}
	signerCert := c.SignerCert(&c.Signers[0])
	if signerCert == nil {
		t.Error("SignerCert not found: подписант контейнера не найден по SID среди сертификатов")
	}
	if signerCert != nil && len(signerCert.SubjectKeyId) == 0 {
		t.Error("SignerCert должен иметь SubjectKeyId")
	}
}
