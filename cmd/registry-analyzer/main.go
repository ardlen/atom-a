// Пакет main — точка входа утилиты анализа контейнеров ATOM-PKCS12-REGISTRY.
//
// registry-analyzer разбирает контейнеры .p12 в формате ATOM-PKCS12-REGISTRY (гибрид PKCS#12 PFX и CMS SignedData),
// извлекает сертификаты из SignedData.certificates и из eContent (SafeContents/SafeBag), атрибуты подписантов (VIN, VER, UID)
// и выводит отчёт в текстовом, JSON или PEM формате. Поддерживается экспорт сертификатов в отдельные PEM-файлы.
//
// Запуск: go run ./cmd/registry-analyzer [опции] <файл.p12>
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgw-registry/registry-analyzer/internal/registry"
)

func main() {
	// Флаги вывода: text — человекочитаемый отчёт; json — полный JSON; json-certificates — только данные сертификатов; pem — PEM-цепочка.
	format := flag.String("format", "text", "Формат вывода: text, json, json-certificates, pem")
	outputPath := flag.String("output", "", "Записать вывод в файл (по умолчанию — stdout)")
	exportCertsDir := flag.String("export-certs-dir", "", "Выгрузить каждый сертификат из SignedData в отдельный PEM-файл в указанную директорию (cert-1.pem, cert-2.pem, ...)")
	exportSafebagCerts := flag.Bool("export-safebag-certs", false, "Выгрузить все сертификаты из SafeBags в один PEM-файл с именем контейнера (например owner_registry.p12 → owner_registry.pem)")
	exportSafebagCertsDir := flag.String("export-safebag-certs-dir", "", "Выгрузить каждый сертификат из SafeBags в отдельный PEM-файл в указанную директорию (имя: roleName_Serial.pem)")
	exportSignerCert := flag.Bool("export-signer-cert", false, "Выгрузить сертификат подписанта контейнера в PEM-файл с именем контейнера (например owner_registry.p12 → owner_registry_signer.pem)")
	noColor := flag.Bool("no-color", false, "Отключить цветной вывод и иконки")
	colorFlag := flag.String("color", "auto", "Цвет: auto (только TTY), always, never")
	flag.Parse()

	// Проверка обязательного аргумента — пути к файлу .p12.
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Использование: %s [опции] <файл.p12>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	path := flag.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "чтение файла: %v\n", err)
		os.Exit(1)
	}

	// Разбор DER-кодированного PFX: извлекаем SignedData, сертификаты, SafeBags и подписантов.
	c, err := registry.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "разбор контейнера: %v\n", err)
		os.Exit(1)
	}

	// Выгрузка каждого сертификата из SignedData в отдельный PEM-файл (имя по roleName подписанта или cert-N).
	if *exportCertsDir != "" {
		if err := os.MkdirAll(*exportCertsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "создание директории %s: %v\n", *exportCertsDir, err)
			os.Exit(1)
		}
		// Избегаем коллизий имён: при повторе добавляем суффикс -2, -3.
		usedNames := make(map[string]int)
		for i, cert := range c.Certificates {
			block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			base := c.CertExportBasename(cert, i) // roleName подписанта или cert-N
			name := base
			if n := usedNames[base]; n > 0 {
				usedNames[base] = n + 1
				name = fmt.Sprintf("%s-%d", base, n+1)
			} else {
				usedNames[base] = 1
			}
			filename := filepath.Join(*exportCertsDir, name+".pem")
			if err := os.WriteFile(filename, pem.EncodeToMemory(block), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "запись %s: %v\n", filename, err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "Выгружено %d сертификатов в %s\n", len(c.Certificates), *exportCertsDir)
	}

	// Выгрузка всех сертификатов из SafeBags в один PEM-файл с именем контейнера.
	if *exportSafebagCerts {
		pemOut, err := c.ToSafeBagsPEM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "export-safebag-certs: %v\n", err)
			os.Exit(1)
		}
		baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if baseName == "" {
			baseName = "registry"
		}
		outPath := filepath.Join(filepath.Dir(path), baseName+".pem")
		if err := os.WriteFile(outPath, pemOut, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "запись %s: %v\n", outPath, err)
			os.Exit(1)
		}
		n := 0
		for _, info := range c.SafeBagInfos {
			if len(info.CertValueDER) > 0 {
				n++
			}
		}
		fmt.Fprintf(os.Stderr, "Сертификаты из SafeBags (%d шт.) записаны в %s\n", n, outPath)
	}

	// Выгрузка каждого сертификата из SafeBags в отдельный PEM-файл (имя: roleName_Serial.pem).
	if *exportSafebagCertsDir != "" {
		if err := os.MkdirAll(*exportSafebagCertsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "создание директории %s: %v\n", *exportSafebagCertsDir, err)
			os.Exit(1)
		}
		usedNames := make(map[string]int)
		n := 0
		for i, info := range c.SafeBagInfos {
			if len(info.CertValueDER) == 0 {
				continue
			}
			block := &pem.Block{Type: "CERTIFICATE", Bytes: info.CertValueDER}
			base := registry.SafeBagExportBasename(&info, i)
			name := base
			if cnt := usedNames[base]; cnt > 0 {
				usedNames[base] = cnt + 1
				name = fmt.Sprintf("%s-%d", base, cnt+1)
			} else {
				usedNames[base] = 1
			}
			filename := filepath.Join(*exportSafebagCertsDir, name+".pem")
			if err := os.WriteFile(filename, pem.EncodeToMemory(block), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "запись %s: %v\n", filename, err)
				os.Exit(1)
			}
			n++
		}
		fmt.Fprintf(os.Stderr, "Выгружено %d сертификатов из SafeBags в %s\n", n, *exportSafebagCertsDir)
	}

	// Выгрузка сертификата подписанта контейнера в отдельный PEM-файл.
	if *exportSignerCert {
		baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if baseName == "" {
			baseName = "registry"
		}
		outPath := filepath.Join(filepath.Dir(path), baseName+"_signer.pem")
		pemOut, err := c.SignerCertPEM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "export-signer-cert: %v\n", err)
			os.Exit(1)
		}
		if len(pemOut) == 0 {
			fmt.Fprintf(os.Stderr, "Сертификат подписанта не найден в контейнере\n")
			os.Exit(1)
		}
		if err := os.WriteFile(outPath, pemOut, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "запись %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Сертификат подписанта записан в %s\n", outPath)
	}

	// Функция вывода: в файл или stdout в зависимости от флага -output.
	writeOut := func(b []byte) {
		if *outputPath != "" {
			if err := os.WriteFile(*outputPath, b, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "запись в файл: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Print(string(b))
		}
	}

	// Формирование и вывод в выбранном формате.
	switch strings.ToLower(*format) {
	case "json":
		out, err := c.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "json: %v\n", err)
			os.Exit(1)
		}
		writeOut(out)
		if *outputPath != "" {
			fmt.Fprintf(os.Stderr, "Полный отчёт записан в %s\n", *outputPath)
		}
	case "json-certificates":
		out, err := c.ToCertificatesJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "json: %v\n", err)
			os.Exit(1)
		}
		writeOut(out)
		if *outputPath != "" {
			fmt.Fprintf(os.Stderr, "Данные сертификатов записаны в %s\n", *outputPath)
		}
	case "pem":
		out, err := c.ToPEM()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pem: %v\n", err)
			os.Exit(1)
		}
		writeOut(out)
		if *outputPath != "" {
			fmt.Fprintf(os.Stderr, "Сертификаты (PEM) записаны в %s\n", *outputPath)
		}
	default:
		// Цветной вывод только в TTY и если не отключён флагами.
		useColor := !*noColor && (*colorFlag == "always" || (*colorFlag != "never" && isTerminal(os.Stdout)))
		var sb strings.Builder
		c.TextOutput(&sb, useColor)
		text := sb.String()
		if *outputPath != "" {
			if err := os.WriteFile(*outputPath, []byte(text), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "запись в файл: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "Текстовый отчёт записан в %s\n", *outputPath)
		} else {
			fmt.Print(text)
		}
	}
}

// isTerminal возвращает true, если f — терминал (в этом случае включается цветной вывод).
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
