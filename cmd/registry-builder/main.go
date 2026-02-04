// Пакет main — утилита сборки реестров ATOM-PKCS12-REGISTRY (registry-builder).
// Создаёт реестры с той же структурой, что и Driver_Certificate_registry.p12 / IVI_Certificate_registry.p12 / owner_registry.p12.
// Имя выходного файла должно начинаться с sgw-. Созданный реестр проверяется утилитой registry-analyzer.
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
	"path/filepath"
	"strings"
	"time"

	"github.com/sgw-registry/registry-analyzer/internal/registry"
)

// Config — конфигурация сборки реестра (JSON).
type Config struct {
	SignerCert   string     `json:"signerCert"`
	SignerKey    string     `json:"signerKey"`
	VIN          string    `json:"vin"`
	VERTimestamp string    `json:"verTimestamp"`
	VERVersion   int       `json:"verVersion"`
	UID          string    `json:"uid"`
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
	outputPath := flag.String("output", "", "Выходной файл реестра (имя должно начинаться с sgw-)")
	flag.Parse()

	if *configPath == "" || *outputPath == "" {
		fmt.Fprintf(os.Stderr, "Использование: %s -config <config.json> -output sgw-<name>.p12\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	baseName := filepath.Base(*outputPath)
	if !strings.HasPrefix(baseName, "sgw-") {
		fmt.Fprintf(os.Stderr, "Имя выходного файла должно начинаться с sgw- (получено: %s)\n", baseName)
		os.Exit(1)
	}

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

	signerCert, signerKey, err := loadSigner(cfg.SignerCert, cfg.SignerKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка подписанта: %v\n", err)
		os.Exit(1)
	}

	safeBags, err := loadSafeBags(cfg.SafeBags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "загрузка SafeBags: %v\n", err)
		os.Exit(1)
	}

	verTime := time.Time{}
	if cfg.VERTimestamp != "" {
		verTime, _ = time.Parse(time.RFC3339, cfg.VERTimestamp)
	}

	attrs := registry.SignerAttrs{
		VIN:           cfg.VIN,
		VERTimestamp:  verTime,
		VERVersion:    cfg.VERVersion,
		UID:           cfg.UID,
	}

	der, err := registry.BuildRegistry(signerCert, signerKey, safeBags, attrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "сборка реестра: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outputPath, der, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "запись %s: %v\n", *outputPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Создан реестр: %s\n", *outputPath)
	fmt.Fprintf(os.Stderr, "Проверка: ./registry-analyzer %s\n", *outputPath)
}

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
