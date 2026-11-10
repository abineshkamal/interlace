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
	Company   string // optional: organisation the report is prepared for
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
	pdf.Cell(0, 12, "Security Assessment")
	pdf.Ln(14)
	pdf.SetFont("Helvetica", "", 11)
	if r.Company != "" {
		pdf.Cell(0, 7, "Prepared for: "+r.Company)
		pdf.Ln(7)
	}
	pdf.Cell(0, 7, "Target: "+r.Target)
	pdf.Ln(7)
	pdf.Cell(0, 7, "Generated: "+r.Generated.Format("2006-01-02 15:04 MST"))
	pdf.Ln(12)

	// Executive summary.
	c := r.counts()
	total := len(r.Findings)
	pdf.SetFont("Helvetica", "B", 15)
	pdf.Cell(0, 8, "Executive Summary")
	pdf.Ln(10)
	pdf.SetFont("Helvetica", "", 11)
	pdf.MultiCell(0, 6, r.summaryNarrative(), "", "L", false)
	pdf.Ln(3)

	// Severity breakdown table.
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetFillColor(238, 240, 247)
	pdf.CellFormat(70, 8, "Severity", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 8, "Count", "1", 1, "C", true, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	for _, s := range []string{"high", "medium", "low", "info"} {
		rr, gg, bb := sevRGB(s)
		pdf.SetTextColor(rr, gg, bb)
		pdf.CellFormat(70, 7, strings.ToUpper(s), "1", 0, "L", false, 0, "")
		pdf.CellFormat(30, 7, fmt.Sprintf("%d", c[s]), "1", 1, "C", false, 0, "")
	}
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(70, 7, "TOTAL", "1", 0, "L", false, 0, "")
	pdf.CellFormat(30, 7, fmt.Sprintf("%d", total), "1", 1, "C", false, 0, "")

	// Detailed findings.
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 15)
	pdf.Cell(0, 8, "Detailed Findings")
	pdf.Ln(11)
	for i, f := range r.sorted() {
		m := MetaFor(f.Check)
		pdf.SetFont("Helvetica", "B", 13)
		rr, gg, bb := sevRGB(f.Severity)
		pdf.SetTextColor(rr, gg, bb)
		pdf.MultiCell(0, 7, fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), "", "L", false)
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "", 10)
		section(pdf, "CVSS v3.1", m.CVSSText())
		section(pdf, "Affected URL", nz(f.URL, f.Host))
		section(pdf, "Observation", m.ObservationText(nz(f.URL, f.Host), f.Detail))
		if f.Evidence != "" {
			pdf.SetFont("Helvetica", "B", 10)
			pdf.Cell(0, 5, "Evidence")
			pdf.Ln(5)
			pdf.SetFont("Courier", "", 9)
			pdf.MultiCell(0, 5, f.Evidence, "", "L", false)
			pdf.SetFont("Helvetica", "", 10)
		}
		section(pdf, "Impact", m.Impact)
		section(pdf, "Recommendation", m.Remediation)
		if ref := m.Reference(); ref != "" {
			section(pdf, "References", ref)
		}
		if f.Note != "" {
			section(pdf, "Analyst note", f.Note)
		}
		if len(f.Screenshot) > 0 {
			name := fmt.Sprintf("shot%d", i)
			opt := fpdf.ImageOptions{ImageType: "PNG", ReadDpi: false}
			if pdf.RegisterImageOptionsReader(name, opt, bytes.NewReader(f.Screenshot)) == nil {
				pdf.Ln(2)
				pdf.ImageOptions(name, 15, pdf.GetY(), 150, 0, true, opt, 0, "")
			}
		}
		pdf.Ln(6)
		pdf.SetDrawColor(220, 220, 220)
		pdf.Line(15, pdf.GetY(), 195, pdf.GetY())
		pdf.Ln(5)
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

// section prints a bold label on its own line followed by a wrapped value.
func section(pdf *fpdf.Fpdf, label, value string) {
	if value == "" {
		return
	}
	pdf.Ln(1)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.Cell(0, 5, label)
	pdf.Ln(5)
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5, value, "", "L", false)
}

func nz(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// summaryNarrative is a one-paragraph overview of the assessment result.
func (r Report) summaryNarrative() string {
	return SummaryText(r.Target, r.counts(), len(r.Findings))
}

// SummaryText renders the executive-summary paragraph from severity counts.
// Exported so the HTML report (in the main package) shares the same wording.
func SummaryText(target string, counts map[string]int, total int) string {
	if total == 0 {
		return "This automated assessment did not identify any issues in the scanned scope. " +
			"Note that automated scanning does not replace manual testing of business logic and access control."
	}
	parts := []string{}
	for _, s := range []string{"high", "medium", "low", "info"} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	lead := "no high-severity issues were found"
	if counts["high"] > 0 {
		lead = fmt.Sprintf("%d high-severity issue(s) require prompt attention", counts["high"])
	}
	return fmt.Sprintf("This assessment of %s identified %d issue(s) (%s). Overall, %s. "+
		"Findings are listed below in order of severity, each with its affected URL, a description, "+
		"the business impact, a recommended remediation and references (CWE / OWASP Top 10).",
		nz(target, "the target"), total, strings.Join(parts, ", "), lead)
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
	f.SetCellValue("Summary", "A1", "Security Assessment")
	if r.Company != "" {
		f.SetCellValue("Summary", "A1", "Security Assessment — "+r.Company)
	}
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
	f.SetCellValue("Summary", cell("A", row), "TOTAL")
	f.SetCellValue("Summary", cell("B", row), len(r.Findings))

	// Findings sheet.
	const sheet = "Findings"
	f.NewSheet(sheet)
	headers := []string{"#", "Severity", "CVSS", "CVSS Vector", "Title", "Affected URL", "Observation", "Impact", "Recommendation", "CWE", "References", "Evidence", "Analyst note"}
	for i, h := range headers {
		col := string(rune('A' + i))
		f.SetCellValue(sheet, col+"1", h)
	}
	for i, fn := range r.sorted() {
		rw := i + 2
		m := MetaFor(fn.Check)
		cvss := "N/A"
		vector := ""
		if m.CVSS > 0 {
			cvss = fmt.Sprintf("%.1f (%s)", m.CVSS, m.CVSSRating())
			vector = "CVSS:3.1/" + m.CVSSVector
		}
		vals := []any{i + 1, fn.Severity, cvss, vector, fn.Title, nz(fn.URL, fn.Host), m.ObservationText(nz(fn.URL, fn.Host), fn.Detail),
			m.Impact, m.Remediation, m.CWE, m.Reference(), fn.Evidence, fn.Note}
		for ci, v := range vals {
			col := string(rune('A' + ci))
			f.SetCellValue(sheet, cell(col, rw), v)
		}
	}
	widths := map[string]float64{"D": 34, "E": 34, "F": 44, "G": 50, "H": 50, "I": 50, "K": 40, "L": 40}
	for col, wdt := range widths {
		f.SetColWidth(sheet, col, col, wdt)
	}

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

	// labeled writes "Label: value" with the label bold and the value normal.
	labeled := func(label, value string) {
		if value == "" {
			return
		}
		body.WriteString(`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">` + xmlEsc(label+": ") + `</w:t></w:r>`)
		body.WriteString(`<w:r><w:t xml:space="preserve">` + xmlEsc(value) + `</w:t></w:r></w:p>`)
	}

	para("Security Assessment", "", true, 20)
	if r.Company != "" {
		para("Prepared for: "+r.Company, "", false, 11)
	}
	para("Target: "+r.Target, "", false, 11)
	para("Generated: "+r.Generated.Format("2006-01-02 15:04 MST"), "", false, 11)
	para("", "", false, 0)

	c := r.counts()
	para("Executive Summary", "", true, 15)
	para(r.summaryNarrative(), "", false, 11)
	para(fmt.Sprintf("High: %d    Medium: %d    Low: %d    Info: %d    Total: %d",
		c["high"], c["medium"], c["low"], c["info"], len(r.Findings)), "", true, 11)
	para("", "", false, 0)

	para("Detailed Findings", "", true, 15)
	for i, f := range r.sorted() {
		m := MetaFor(f.Check)
		para(fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), "", true, 14)
		labeled("CVSS v3.1", m.CVSSText())
		labeled("Affected URL", nz(f.URL, f.Host))
		labeled("Observation", m.ObservationText(nz(f.URL, f.Host), f.Detail))
		if f.Evidence != "" {
			labeled("Evidence", f.Evidence)
		}
		labeled("Impact", m.Impact)
		labeled("Recommendation", m.Remediation)
		if ref := m.Reference(); ref != "" {
			labeled("References", ref)
		}
		if f.Note != "" {
			labeled("Analyst note", f.Note)
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
