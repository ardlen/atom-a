// Пакет main — точка входа утилиты анализа контейнеров CMS/PKCS#7 (.p7).
//
// p7-analyzer читает файл .p7 (PEM с -----BEGIN CMS-----/-----END CMS----- или DER),
// разбирает ContentInfo → SignedData, извлекает сертификаты из certificates и из eContent (PEM),
// выводит отчёт и поддерживает экспорт сертификатов в PEM.
//
// Запуск: go run ./cmd/p7-analyzer [опции] <файл.p7>
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgw-registry/registry-analyzer/internal/cms"
)

func main() {
	format := flag.String("format", "text", "Формат вывода: text, json, pem")
	outputPath := flag.String("output", "", "Записать вывод в файл (по умолчанию — stdout)")
	exportCertsDir := flag.String("export-certs-dir", "", "Выгрузить каждый сертификат из SignedData.certificates в отдельный PEM в директорию (cert-1.pem, ...)")
	exportAllCerts := flag.Bool("export-all-certs", false, "Выгрузить все сертификаты (SignedData + eContent) в один PEM с именем контейнера (file.p7 → file.pem)")
	exportEContentCertsDir := flag.String("export-econtent-certs-dir", "", "Выгрузить каждый сертификат из eContent в отдельный PEM в директорию (econtent-1.pem, ...)")
	exportSignerCert := flag.Bool("export-signer-cert", false, "Выгрузить сертификат подписанта в PEM (file.p7 → file_signer.pem)")
	noColor := flag.Bool("no-color", false, "Отключить цветной вывод и иконки")
	colorFlag := flag.String("color", "auto", "Цвет: auto (только TTY), always, never")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Использование: %s [опции] <файл.p7>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	path := flag.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение файла: %v\n", err)
		os.Exit(1)
	}

	// Разбор: PEM (BEGIN CMS / PKCS7) или сырой DER
	var container *cms.Container
	if isPEM(data) {
		container, err = cms.ParseCMSFromPEM(data)
	} else {
		container, err = cms.ParseCMS(data)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "разбор CMS: %v\n", err)
		os.Exit(1)
	}

	baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	if baseName == "" {
		baseName = "p7"
	}
	dir := filepath.Dir(path)

	// Экспорты
	if *exportCertsDir != "" {
		if err := os.MkdirAll(*exportCertsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "создание директории %s: %v\n", *exportCertsDir, err)
			os.Exit(1)
		}
		n, err := container.ExportCertsToDir(*exportCertsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "export-certs-dir: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Выгружено %d сертификатов из SignedData в %s\n", n, *exportCertsDir)
	}
	if *exportAllCerts {
		outPath := filepath.Join(dir, baseName+".pem")
		if err := os.WriteFile(outPath, container.ToAllCertsPEM(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "export-all-certs: %v\n", err)
			os.Exit(1)
		}
		total := len(container.Certificates) + len(container.EContentCerts)
		fmt.Fprintf(os.Stderr, "Все сертификаты (%d шт.) записаны в %s\n", total, outPath)
	}
	if *exportEContentCertsDir != "" {
		if err := os.MkdirAll(*exportEContentCertsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "создание директории %s: %v\n", *exportEContentCertsDir, err)
			os.Exit(1)
		}
		n, err := container.ExportEContentCertsToDir(*exportEContentCertsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "export-econtent-certs-dir: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Выгружено %d сертификатов из eContent в %s\n", n, *exportEContentCertsDir)
	}
	if *exportSignerCert {
		outPath := filepath.Join(dir, baseName+"_signer.pem")
		if err := container.ExportSignerCert(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "export-signer-cert: %v (подписант не найден среди certificates/eContent)\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Сертификат подписанта записан в %s\n", outPath)
		}
	}

	// Вывод отчёта
	useColor := !*noColor && (*colorFlag == "always" || (*colorFlag != "never" && isTerminal(os.Stdout)))
	var out []byte
	switch *format {
	case "text":
		out = []byte(container.ToText(useColor))
	case "json":
		out, err = container.ToJSON(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "JSON: %v\n", err)
			os.Exit(1)
		}
	case "pem":
		out = container.ToAllCertsPEM()
	default:
		fmt.Fprintf(os.Stderr, "неизвестный формат: %s\n", *format)
		os.Exit(1)
	}

	if *outputPath != "" {
		if err := os.WriteFile(*outputPath, out, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "запись %s: %v\n", *outputPath, err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(out)
	}
}

func isPEM(data []byte) bool {
	const begin = "-----BEGIN "
	return bytes.Contains(data, []byte(begin))
}

// isTerminal возвращает true, если f — терминал (включается цветной вывод).
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
