// Package report renders a set of security findings into downloadable report
// formats: PDF, Excel (.xlsx) and Word (.docx). HTML is produced by the main
// package's existing template. Screenshots (PNG) are embedded in the PDF; the
// Excel and Word outputs are tabular/text (screenshots live in the PDF/HTML).
//
// All renderers are pure Go, preserving Interlace's single-binary, CGO-free build.
package report

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/xuri/excelize/v2"
)

// Finding is the report-facing view of a stored finding.
type Finding struct {
	Severity   string
	Title      string
	Host       string
	URL        string
	Check      string
	Detail     string
	Evidence   string
	Note       string
	ReqRaw     string
	RespRaw    string
	Screenshot []byte // PNG, optional
}

// Report is the full document model.
type Report struct {
	Target    string
	Generated time.Time
	Findings  []Finding
}

var sevOrder = map[string]int{"high": 0, "medium": 1, "low": 2, "info": 3}

func (r Report) counts() map[string]int {
	c := map[string]int{"high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range r.Findings {
		c[f.Severity]++
	}
	return c
}

func (r Report) sorted() []Finding {
	fs := append([]Finding(nil), r.Findings...)
	sort.SliceStable(fs, func(i, j int) bool { return sevOrder[fs[i].Severity] < sevOrder[fs[j].Severity] })
	return fs
}

// ---- PDF ----

// PDF renders the report as a PDF document with embedded screenshots.
func (r Report) PDF() ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)

	// Title page header.
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 22)
	pdf.Cell(0, 12, "Interlace Security Assessment")
	pdf.Ln(14)
	pdf.SetFont("Helvetica", "", 11)
	pdf.Cell(0, 7, "Target: "+r.Target)
	pdf.Ln(7)
	pdf.Cell(0, 7, "Generated: "+r.Generated.Format("2006-01-02 15:04 MST"))
	pdf.Ln(12)

	// Summary.
	c := r.counts()
	pdf.SetFont("Helvetica", "B", 13)
	pdf.Cell(0, 8, "Summary")
	pdf.Ln(9)
	pdf.SetFont("Helvetica", "", 11)
	for _, s := range []string{"high", "medium", "low", "info"} {
		rr, gg, bb := sevRGB(s)
		pdf.SetTextColor(rr, gg, bb)
		pdf.Cell(0, 7, fmt.Sprintf("%s: %d", strings.ToUpper(s), c[s]))
		pdf.Ln(7)
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(4)

	// Findings.
	for i, f := range r.sorted() {
		pdf.SetFont("Helvetica", "B", 13)
		rr, gg, bb := sevRGB(f.Severity)
		pdf.SetTextColor(rr, gg, bb)
		pdf.MultiCell(0, 7, fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "", 10)
		kv(pdf, "Host", f.Host)
		kv(pdf, "URL", f.URL)
		kv(pdf, "Check", f.Check)
		if f.Detail != "" {
			pdf.Ln(1)
			pdf.MultiCell(0, 5, f.Detail, "", "L", false)
		}
		if f.Evidence != "" {
			pdf.SetFont("Courier", "", 9)
			pdf.MultiCell(0, 5, "Evidence: "+f.Evidence, "", "L", false)
			pdf.SetFont("Helvetica", "", 10)
		}
		if f.Note != "" {
			pdf.MultiCell(0, 5, "Analyst note: "+f.Note, "", "L", false)
		}
		if len(f.Screenshot) > 0 {
			name := fmt.Sprintf("shot%d", i)
			opt := fpdf.ImageOptions{ImageType: "PNG", ReadDpi: false}
			if pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(f.Screenshot)) != nil {
				// skip a bad image silently
			} else {
				pdf.Ln(2)
				// fit within the content width (180mm)
				pdf.ImageOptions(name, 15, pdf.GetY(), 150, 0, true, opt, 0, "")
			}
		}
		pdf.Ln(6)
		pdf.SetDrawColor(220, 220, 220)
		pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
		pdf.Ln(4)
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func kv(pdf *fpdf.Fpdf, k, v string) {
	if v == "" {
		return
	}
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(22, 5, k+":")
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5, v, "", "L", false)
}

func sevRGB(s string) (int, int, int) {
	switch s {
	case "high":
		return 192, 32, 32
	case "medium":
		return 200, 120, 0
	case "low":
		return 40, 110, 190
	default:
		return 90, 90, 90
	}
}

// ---- Excel ----

// XLSX renders the report as an Excel workbook (Summary + Findings sheets).
func (r Report) XLSX() ([]byte, error) {
	f := excelize.NewFile()
	defer f.Close()

	// Summary sheet.
	f.SetSheetName("Sheet1", "Summary")
	f.SetCellValue("Summary", "A1", "Interlace Security Assessment")
	f.SetCellValue("Summary", "A2", "Target")
	f.SetCellValue("Summary", "B2", r.Target)
	f.SetCellValue("Summary", "A3", "Generated")
	f.SetCellValue("Summary", "B3", r.Generated.Format("2006-01-02 15:04 MST"))
	c := r.counts()
	row := 5
	f.SetCellValue("Summary", "A4", "Severity")
	f.SetCellValue("Summary", "B4", "Count")
	for _, s := range []string{"high", "medium", "low", "info"} {
		f.SetCellValue("Summary", cell("A", row), strings.ToUpper(s))
		f.SetCellValue("Summary", cell("B", row), c[s])
		row++
	}

	// Findings sheet.
	const sheet = "Findings"
	f.NewSheet(sheet)
	headers := []string{"#", "Severity", "Title", "Host", "URL", "Check", "Evidence", "Note"}
	for i, h := range headers {
		col := string(rune('A' + i))
		f.SetCellValue(sheet, col+"1", h)
	}
	for i, fn := range r.sorted() {
		rw := i + 2
		vals := []any{i + 1, fn.Severity, fn.Title, fn.Host, fn.URL, fn.Check, fn.Evidence, fn.Note}
		for ci, v := range vals {
			col := string(rune('A' + ci))
			f.SetCellValue(sheet, cell(col, rw), v)
		}
	}
	f.SetColWidth(sheet, "C", "C", 40)
	f.SetColWidth(sheet, "E", "E", 40)
	f.SetColWidth(sheet, "G", "G", 50)

	buf, err := f.WriteToBuffer()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func cell(col string, row int) string { return fmt.Sprintf("%s%d", col, row) }

// ---- Word (.docx) ----

// DOCX renders the report as a minimal, valid Word document (text/tabular;
// screenshots are in the PDF/HTML). It hand-writes the OOXML package so it needs
// no external library.
func (r Report) DOCX() ([]byte, error) {
	var body strings.Builder
	para := func(text, style string, bold bool, sz int) {
		body.WriteString(`<w:p>`)
		if style != "" {
			body.WriteString(`<w:pPr><w:pStyle w:val="` + style + `"/></w:pPr>`)
		}
		body.WriteString(`<w:r><w:rPr>`)
		if bold {
			body.WriteString(`<w:b/>`)
		}
		if sz > 0 {
			body.WriteString(fmt.Sprintf(`<w:sz w:val="%d"/>`, sz*2))
		}
		body.WriteString(`</w:rPr><w:t xml:space="preserve">` + xmlEsc(text) + `</w:t></w:r></w:p>`)
	}

	para("Interlace Security Assessment", "", true, 20)
	para("Target: "+r.Target, "", false, 11)
	para("Generated: "+r.Generated.Format("2006-01-02 15:04 MST"), "", false, 11)
	c := r.counts()
	para(fmt.Sprintf("Summary — High: %d   Medium: %d   Low: %d   Info: %d",
		c["high"], c["medium"], c["low"], c["info"]), "", true, 12)
	para("", "", false, 0)

	for i, f := range r.sorted() {
		para(fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), "", true, 14)
		para("Host: "+f.Host, "", false, 11)
		if f.URL != "" {
			para("URL: "+f.URL, "", false, 11)
		}
		para("Check: "+f.Check, "", false, 11)
		if f.Detail != "" {
			para(f.Detail, "", false, 11)
		}
		if f.Evidence != "" {
			para("Evidence: "+f.Evidence, "", false, 10)
		}
		if f.Note != "" {
			para("Analyst note: "+f.Note, "", false, 10)
		}
		if len(f.Screenshot) > 0 {
			para("[screenshot captured — see PDF/HTML report]", "", false, 10)
		}
		para("", "", false, 0)
	}

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>` + body.String() + `</w:body></w:document>`

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := []struct{ name, data string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", document},
	}
	for _, fl := range files {
		w, err := zw.Create(fl.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(fl.data)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func xmlEsc(s string) string {
	// Reuse html escaping (covers &, <, >, quotes) which is valid for XML text.
	return html.EscapeString(s)
}
