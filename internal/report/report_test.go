package report

import (
	"archive/zip"
	"bytes"
	"testing"
	"time"
)

func sampleReport() Report {
	return Report{
		Target:    "app.example.com",
		Generated: time.Date(2026, 1, 2, 15, 4, 0, 0, time.UTC),
		Findings: []Finding{
			{Severity: "high", Title: "Reflected XSS", Host: "app.example.com", URL: "http://app.example.com/search?q=x", Check: "reflected-xss", Detail: "User input reflected without encoding.", Evidence: "payload reflected"},
			{Severity: "medium", Title: "Missing CSP", Host: "app.example.com", Check: "missing-csp", Detail: "No Content-Security-Policy header."},
			{Severity: "low", Title: "Cookie without SameSite", Host: "app.example.com", Check: "cookie-no-samesite"},
		},
	}
}

func TestPDF(t *testing.T) {
	b, err := sampleReport().PDF()
	if err != nil {
		t.Fatalf("PDF: %v", err)
	}
	if len(b) < 500 || !bytes.HasPrefix(b, []byte("%PDF")) {
		t.Errorf("not a PDF (len=%d, prefix=%q)", len(b), b[:min(4, len(b))])
	}
}

func TestXLSX(t *testing.T) {
	b, err := sampleReport().XLSX()
	if err != nil {
		t.Fatalf("XLSX: %v", err)
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("xlsx is not a valid zip: %v", err)
	}
	if !hasPart(z, "xl/workbook.xml") {
		t.Error("xlsx missing xl/workbook.xml")
	}
}

func TestDOCX(t *testing.T) {
	b, err := sampleReport().DOCX()
	if err != nil {
		t.Fatalf("DOCX: %v", err)
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}
	if !hasPart(z, "word/document.xml") || !hasPart(z, "[Content_Types].xml") {
		t.Error("docx missing required parts")
	}
	// The document body should carry a finding title.
	for _, f := range z.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			rc.Close()
			if !bytes.Contains(buf.Bytes(), []byte("Reflected XSS")) {
				t.Error("docx body missing finding title")
			}
		}
	}
}

func hasPart(z *zip.Reader, name string) bool {
	for _, f := range z.File {
		if f.Name == name {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
