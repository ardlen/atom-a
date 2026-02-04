package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParse проверяет разбор контейнера: загружает owner_registry.p12 (из текущей директории или выше по дереву)
// и проверяет, что PFX version=3, contentType=pkcs7-signedData, есть хотя бы один сертификат и один подписант.
func TestParse(t *testing.T) {
	paths := []string{
		"owner_registry.p12",
		"../owner_registry.p12",
		"../../owner_registry.p12",
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Skipf("тестовый файл .p12 не найден: %v", err)
		return
	}

	c, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.PFXVersion != 3 {
		t.Errorf("PFX version = %d, ожидается 3", c.PFXVersion)
	}
	if !c.ContentType.Equal(OIDPKCS7SignedData) {
		t.Errorf("contentType = %v, ожидается pkcs7-signedData", c.ContentType)
	}
	if len(c.Certificates) == 0 {
		t.Error("ожидается хотя бы один сертификат")
	}
	if len(c.Signers) == 0 {
		t.Error("ожидается хотя бы один подписант")
	}
}

// TestParseFile проверяет разбор файла из корня репозитория и наличие атрибута VIN у первого подписанта.
// Запуск из корня: go test -run TestParseFile ./internal/registry
func TestParseFile(t *testing.T) {
	path := filepath.Join("..", "..", "owner_registry.p12")
	if _, err := os.Stat(path); err != nil {
		t.Skip("owner_registry.p12 не найден")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Signers) == 0 {
		t.Fatal("нет подписантов")
	}
	attrs, err := SignerAttributes(&c.Signers[0])
	if err != nil {
		t.Fatal(err)
	}
	var hasVIN bool
	for _, a := range attrs {
		if a.AttrType.Equal(OIDAtomVIN) {
			hasVIN = true
			break
		}
	}
	if !hasVIN {
		t.Error("ожидается атрибут VIN у первого подписанта")
	}
}
