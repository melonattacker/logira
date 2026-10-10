package htmlreport

import (
	"embed"
	"html/template"
	"io"
)

//go:embed report.html
var templates embed.FS

var standaloneTemplate = template.Must(template.New("report.html").ParseFS(templates, "report.html"))

// Render writes one deterministic, standalone HTML document.
func Render(w io.Writer, report Report) error {
	return standaloneTemplate.ExecuteTemplate(w, "report.html", report)
}
