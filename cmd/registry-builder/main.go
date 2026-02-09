// Пакет main — утилита сборки реестров ATOM-PKCS12-REGISTRY (registry-builder).
//
// registry-builder создаёт .p12 контейнеры по JSON-конфигу: подписант (сертификат + ключ ECDSA),
// атрибуты подписанта (VIN, VER, UID), список SafeBags (сертификаты ролей с roleName, roleValidityPeriod, localKeyID).
// Структура вывода соответствует эталону (полный SignedData в content [0], OCTET STRING eContent, сортировка атрибутов по DER).
// Созданный реестр можно проверить утилитой registry-analyzer.
//
// Запуск: go run ./cmd/registry-builder -config <config.json> -output <имя>.p12
package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sgw-registry/registry-analyzer/internal/registry"
)

// Config — конфигурация сборки реестра (JSON).
type Config struct {
	SignerCert   string          `json:"signerCert"`
	SignerKey    string          `json:"signerKey"`
	VIN          string          `json:"vin"`
	VERTimestamp string          `json:"verTimestamp"`
	VERVersion   int             `json:"verVersion"`
	UID          string          `json:"uid"`
	SafeBags     []SafeBagConfig `json:"safeBags"`
}

// SafeBagConfig — один мешок в конфиге: путь к сертификату и атрибуты.
type SafeBagConfig struct {
	Cert          string `json:"cert"`
	RoleName      string `json:"roleName"`
	RoleNotBefore string `json:"roleNotBefore"`
	RoleNotAfter  string `json:"roleNotAfter"`
	LocalKeyID    string `json:"localKeyID"` // hex
}

func main() {
	configPath := flag.String("config", "", "Путь к JSON-конфигу (signerCert, signerKey, vin, verTimestamp, verVersion, uid, safeBags)")
	outputPath := flag.String("output", "", "Выходной файл реестра (.p12)")
	flag.Parse()

	// Оба параметра обязательны.
	if *configPath == "" || *outputPath == "" {
		fmt.Fprintf(os.Stderr, "Использование: %s -config <config.json> -output <имя>.p12\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Загрузка и разбор JSON-конфига.
	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение конфига: %v\n", err)
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "разбор конфига: %v\n", err)
		os.Exit(1)
	}

	// Загрузка сертификата и ключа подписанта из PEM-файлов.
	signerCert, signerKey, err := loadSigner(cfg.SignerCert, cfg.SignerKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка подписанта: %v\n", err)
		os.Exit(1)
	}

	// Загрузка сертификатов ролей и атрибутов мешков из конфига.
	safeBags, err := loadSafeBags(cfg.SafeBags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка SafeBags: %v\n", err)
		os.Exit(1)
	}

	// Парсинг времени версии (опционально).
	verTime := time.Time{}
	if cfg.VERTimestamp != "" {
		verTime, _ = time.Parse(time.RFC3339, cfg.VERTimestamp)
	}

	// Атрибуты подписанта для SignerInfo.authenticatedAttributes [0] (VIN, VER, UID).
	attrs := registry.SignerAttrs{
		VIN:          cfg.VIN,
		VERTimestamp: verTime,
		VERVersion:   cfg.VERVersion,
		UID:          cfg.UID,
	}

	// Сборка DER-кодированного PFX (PFX → authSafe ContentInfo → SignedData → signerInfos, eContent, certificates).
	der, err := registry.BuildRegistry(signerCert, signerKey, safeBags, attrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "сборка реестра: %v\n", err)
		os.Exit(1)
	}

	// Запись результата в выходной файл.
	if err := os.WriteFile(*outputPath, der, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "запись %s: %v\n", *outputPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Создан реестр: %s\n", *outputPath)
	fmt.Fprintf(os.Stderr, "Проверка: ./registry-analyzer %s\n", *outputPath)
}

// loadSigner загружает сертификат подписанта и приватный ключ ECDSA из PEM-файлов.
// Возвращает (*x509.Certificate, *ecdsa.PrivateKey, error). Ключ должен соответствовать публичному ключу сертификата.
func loadSigner(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("signer cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("signer cert: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("signer cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("signer key: %w", err)
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("signer key: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("signer key: %w", err)
	}

	return cert, key, nil
}

// loadSafeBags преобразует конфиг мешков в формат registry.SafeBagInput.
// Для каждого мешка: читает сертификат из PEM, парсит roleNotBefore/roleNotAfter (RFC3339), декодирует localKeyID (hex).
func loadSafeBags(cfgs []SafeBagConfig) ([]registry.SafeBagInput, error) {
	var out []registry.SafeBagInput
	for i, c := range cfgs {
		certPEM, err := os.ReadFile(c.Cert)
		if err != nil {
			return nil, fmt.Errorf("safeBags[%d] cert %s: %w", i, c.Cert, err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("safeBags[%d] cert: no PEM block", i)
		}

		var localKeyID []byte
		if c.LocalKeyID != "" {
			localKeyID, err = hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(c.LocalKeyID), "0x"))
			if err != nil {
				return nil, fmt.Errorf("safeBags[%d] localKeyID: %w", i, err)
			}
		}

		var nb, na time.Time
		if c.RoleNotBefore != "" {
			nb, _ = time.Parse(time.RFC3339, c.RoleNotBefore)
		}
		if c.RoleNotAfter != "" {
			na, _ = time.Parse(time.RFC3339, c.RoleNotAfter)
		}

		out = append(out, registry.SafeBagInput{
			CertDER:       block.Bytes,
			RoleName:      c.RoleName,
			RoleNotBefore: nb,
			RoleNotAfter:  na,
			LocalKeyID:    localKeyID,
		})
	}
	return out, nil
}
