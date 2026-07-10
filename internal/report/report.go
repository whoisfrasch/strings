package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	htmltmpl "html/template"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/threat"
)

//go:embed template.html
var htmlTemplate string

var tmpl = template.Must(template.New("report").Parse(htmlTemplate))

type templateData struct {
	FileName     string
	FileSize     string
	SectionCount int
	Timestamp    string
	LevelColor   string
	ThreatLevel  string
	ThreatScore  int
	TotalStr     string
	HighEntropy  int
	Suspicious   int
	Base64Count  int
	XorCount     int
	ResultsJSON  htmltmpl.JS
}

func Generate(results []internal.StringResult, filePath string, sections []internal.SectionInfo, outputPath string) error {
	sourceCounts := make(map[string]int)
	highEntropy := 0
	suspicious := 0
	for _, r := range results {
		sourceCounts[r.Source]++
		if r.Entropy >= 4.5 {
			highEntropy++
		}
		if r.SuspiciousGroup != "" {
			suspicious++
		}
	}

	t := threat.Assess(results)
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filePath, err)
	}

	type jsonEntry struct {
		Value    string   `json:"value"`
		Offset   int64    `json:"offset"`
		Encoding string   `json:"encoding"`
		Section  string   `json:"section"`
		Cats     []string `json:"categories"`
		Entropy  float64  `json:"entropy"`
		EntLabel string   `json:"entropy_label"`
		APIGroup string   `json:"api_group"`
		Source   string   `json:"source"`
		XorKey   byte     `json:"xor_key"`
		Length   int      `json:"length"`
	}

	entries := make([]jsonEntry, len(results))
	for i, r := range results {
		val := r.Value
		if len(val) > 500 {
			val = truncateUTF8(val, 500)
		}
		entries[i] = jsonEntry{
			Value: val, Offset: r.Offset, Encoding: r.Encoding,
			Section: r.Section, Cats: r.Categories, Entropy: r.Entropy,
			EntLabel: r.EntropyLabel, APIGroup: r.SuspiciousGroup,
			Source: r.Source, XorKey: r.XorKey, Length: r.Length,
		}
	}

	resultsJSON, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal results: %w", err)
	}
	safeJSON := strings.ReplaceAll(string(resultsJSON), "</script>", `<\/script>`)
	safeJSON = strings.ReplaceAll(safeJSON, "</Script>", `<\/Script>`)

	levelColor := map[string]string{"LOW": "#30a46c", "MEDIUM": "#f5d90a", "HIGH": "#e5484d", "CRITICAL": "#e5484d"}[t.Level]

	data := templateData{
		FileName:     filepath.Base(filePath),
		FileSize:     internal.FormatSize(info.Size()),
		SectionCount: len(sections),
		Timestamp:    time.Now().Format("2006-01-02 15:04:05"),
		LevelColor:   levelColor,
		ThreatLevel:  t.Level,
		ThreatScore:  t.Score,
		TotalStr:     formatNum(len(results)),
		HighEntropy:  highEntropy,
		Suspicious:   suspicious,
		Base64Count:  sourceCounts["base64"],
		XorCount:     sourceCounts["xor"],
		ResultsJSON:  htmltmpl.JS(safeJSON),
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

func formatNum(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
