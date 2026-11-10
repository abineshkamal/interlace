package report

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Report templating: fill a user-supplied .docx template with the assessment
// data. The template uses {{placeholders}} in its text. Word often splits a
// placeholder across several runs, so we flatten each paragraph's runs before
// substituting. Supported scalar placeholders:
//
//	{{company}} {{target}} {{date}} {{total}} {{high}} {{medium}} {{low}} {{info}} {{summary}}
//
// and one block placeholder, {{findings}}, which is replaced by the full,
// formatted detailed-findings section.
var (
	wpRe   = regexp.MustCompile(`(?s)<w:p\b[^>]*>.*?</w:p>`)
	wtRe   = regexp.MustCompile(`(?s)<w:t[^>]*>(.*?)</w:t>`)
	wpPrRe = regexp.MustCompile(`(?s)<w:pPr>.*?</w:pPr>`)
	wrPrRe = regexp.MustCompile(`(?s)<w:rPr>.*?</w:rPr>`)
)

// TemplatePlaceholders lists the placeholders a template may use (for the UI).
var TemplatePlaceholders = []string{
	"{{company}}", "{{target}}", "{{date}}", "{{total}}",
	"{{high}}", "{{medium}}", "{{low}}", "{{info}}", "{{summary}}", "{{findings}}",
}

// FillTemplate returns a .docx built by substituting this report's data into the
// supplied .docx template bytes.
func (r Report) FillTemplate(tmpl []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(tmpl), int64(len(tmpl)))
	if err != nil {
		return nil, fmt.Errorf("not a valid .docx template: %w", err)
	}
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	found := false
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		if zf.Name == "word/document.xml" {
			found = true
			data = []byte(r.fillDocXML(string(data)))
		}
		w, err := zw.Create(zf.Name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("template has no word/document.xml")
	}
	return out.Bytes(), nil
}

func (r Report) fillDocXML(doc string) string {
	c := r.counts()
	scalars := map[string]string{
		"{{company}}": r.Company,
		"{{target}}":  r.Target,
		"{{date}}":    r.Generated.Format("2006-01-02 15:04 MST"),
		"{{total}}":   fmt.Sprint(len(r.Findings)),
		"{{high}}":    fmt.Sprint(c["high"]),
		"{{medium}}":  fmt.Sprint(c["medium"]),
		"{{low}}":     fmt.Sprint(c["low"]),
		"{{info}}":    fmt.Sprint(c["info"]),
		"{{summary}}": r.summaryNarrative(),
	}
	return wpRe.ReplaceAllStringFunc(doc, func(p string) string {
		// Concatenate the paragraph's run text to reassemble split placeholders.
		var text strings.Builder
		for _, m := range wtRe.FindAllStringSubmatch(p, -1) {
			text.WriteString(m[1])
		}
		t := text.String()
		if !strings.Contains(t, "{{") {
			return p // untouched — preserves all original formatting
		}
		if strings.Contains(t, "{{findings}}") {
			return r.docxFindingsXML()
		}
		for k, v := range scalars {
			t = strings.ReplaceAll(t, k, xmlEsc(v))
		}
		// Rebuild as a single run, preserving the paragraph style (pPr) and the
		// first run's inline formatting (rPr) so bold/size/font carry over.
		pPr := wpPrRe.FindString(p)
		rest := p
		if pPr != "" {
			rest = strings.Replace(p, pPr, "", 1)
		}
		rPr := wrPrRe.FindString(rest)
		return "<w:p>" + pPr + "<w:r>" + rPr + `<w:t xml:space="preserve">` + t + `</w:t></w:r></w:p>`
	})
}

// docxFindingsXML renders the detailed findings as OOXML paragraphs for the
// {{findings}} block placeholder.
func (r Report) docxFindingsXML() string {
	var b strings.Builder
	para := func(text string, bold bool, sz int) {
		b.WriteString(`<w:p><w:r><w:rPr>`)
		if bold {
			b.WriteString(`<w:b/>`)
		}
		if sz > 0 {
			b.WriteString(fmt.Sprintf(`<w:sz w:val="%d"/>`, sz*2))
		}
		b.WriteString(`</w:rPr><w:t xml:space="preserve">` + xmlEsc(text) + `</w:t></w:r></w:p>`)
	}
	labeled := func(label, value string) {
		if value == "" {
			return
		}
		b.WriteString(`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">` + xmlEsc(label+": ") + `</w:t></w:r>`)
		b.WriteString(`<w:r><w:t xml:space="preserve">` + xmlEsc(value) + `</w:t></w:r></w:p>`)
	}
	for i, f := range r.sorted() {
		m := MetaFor(f.Check)
		para(fmt.Sprintf("%d. [%s] %s", i+1, strings.ToUpper(f.Severity), f.Title), true, 14)
		labeled("CVSS v3.1", m.CVSSText())
		labeled("Affected URL", nz(f.URL, f.Host))
		labeled("Description", nz(f.Detail, "An instance of "+f.Title+" was identified."))
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
		para("", false, 0)
	}
	return b.String()
}
