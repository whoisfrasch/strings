package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/color"
	"github.com/whoisfrasch/strings/internal/threat"
)

// Config holds output configuration flags.
type Config struct {
	Color   *color.Colorizer
	Offset  bool
	Context bool
	Quiet   bool
}

// PrintText writes results in human-readable colored text format.
func PrintText(results []internal.StringResult, cfg *Config) {
	col := cfg.Color
	for _, r := range results {
		var parts []string

		if cfg.Offset {
			parts = append(parts, col.Apply(fmt.Sprintf("0x%08X", r.Offset), "gray"))
		}
		if r.Section != "" {
			parts = append(parts, col.Apply(fmt.Sprintf("[%s]", r.Section), "dim"))
		}
		if r.Source != "raw" {
			src := fmt.Sprintf("[%s", r.Source)
			if r.Source == "xor" {
				src += fmt.Sprintf(" 0x%02X", r.XorKey)
			}
			src += "]"
			sc := "cyan"
			if r.Source == "xor" {
				sc = "red"
			}
			parts = append(parts, col.Apply(src, sc))
		}

		var tags []string
		for _, c := range r.Categories {
			if c != "general" {
				tags = append(tags, col.Apply(c, color.CategoryColor(c)))
			}
		}
		if len(tags) > 0 {
			parts = append(parts, strings.Join(tags, " "))
		}
		if r.Entropy >= 4.5 {
			parts = append(parts, col.Apply(fmt.Sprintf("H:%.1f", r.Entropy), "red"))
		}

		parts = append(parts, r.Value)
		fmt.Println(strings.Join(parts, "  "))

		if cfg.Context && (r.HexBefore != "" || r.HexAfter != "") {
			fmt.Printf("    %s %s\n", col.Apply("before:", "dim"), r.HexBefore)
			fmt.Printf("    %s  %s\n", col.Apply("after:", "dim"), r.HexAfter)
		}
	}
}

// PrintJSON writes results in JSON format.
func PrintJSON(results []internal.StringResult, fp string) {
	t := threat.Assess(results)
	out := struct {
		File    string                  `json:"file"`
		Count   int                     `json:"count"`
		Threat  internal.ThreatResult   `json:"threat"`
		Strings []internal.StringResult `json:"strings"`
	}{fp, len(results), t, results}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(out)
}

// PrintCSV writes results in CSV format.
func PrintCSV(results []internal.StringResult) {
	w := csv.NewWriter(os.Stdout)
	w.Write([]string{"offset", "encoding", "section", "categories", "entropy", "source", "xor_key", "api_group", "value"})
	for _, r := range results {
		w.Write([]string{
			fmt.Sprintf("%d", r.Offset), r.Encoding, r.Section,
			strings.Join(r.Categories, ";"), fmt.Sprintf("%.2f", r.Entropy),
			r.Source, fmt.Sprintf("%d", r.XorKey), r.SuspiciousGroup, r.Value,
		})
	}
	w.Flush()
}

// PrintStats writes statistics to stderr.
func PrintStats(results []internal.StringResult, fp string, sections []internal.SectionInfo, col *color.Colorizer) {
	catCounts := make(map[string]int)
	srcCounts := make(map[string]int)
	highEnt := 0
	susCount := 0
	for _, r := range results {
		for _, c := range r.Categories {
			catCounts[c]++
		}
		srcCounts[r.Source]++
		if r.Entropy >= 4.5 {
			highEnt++
		}
		if r.SuspiciousGroup != "" {
			susCount++
		}
	}

	W := 54
	fmt.Fprintf(os.Stderr, "\n  %s\n", strings.Repeat("=", W))
	fmt.Fprintf(os.Stderr, "  %s\n", col.Apply(filepath.Base(fp), "bold"))
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Total strings:       %8d\n", len(results))
	fmt.Fprintf(os.Stderr, "  High entropy (>=4.5):%8d\n", highEnt)
	fmt.Fprintf(os.Stderr, "  Suspicious APIs:     %8d\n", susCount)
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Sources:\n")
	for src, cnt := range srcCounts {
		fmt.Fprintf(os.Stderr, "    %-12s  %8d\n", src, cnt)
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
	fmt.Fprintf(os.Stderr, "  Top categories:\n")
	for cat, cnt := range catCounts {
		fmt.Fprintf(os.Stderr, "    %-20s  %8d\n", col.Apply(cat, color.CategoryColor(cat)), cnt)
	}
	if len(sections) > 0 {
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", W))
		fmt.Fprintf(os.Stderr, "  Sections:\n")
		for _, sec := range sections {
			fmt.Fprintf(os.Stderr, "    %-12s  offset=0x%08X  size=%s\n", sec.Name, sec.Offset, internal.FormatSize(sec.Size))
		}
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("=", W))
}

// PrintThreat writes threat assessment to stderr.
func PrintThreat(results []internal.StringResult, col *color.Colorizer) {
	t := threat.Assess(results)
	lc := map[string]string{"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "red"}[t.Level]

	fmt.Fprintf(os.Stderr, "\n  %s\n", strings.Repeat("=", 54))
	fmt.Fprintf(os.Stderr, "  %s\n", col.Apply("THREAT ASSESSMENT", "bold"))
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("=", 54))
	fmt.Fprintf(os.Stderr, "  Level: %s (score: %d)\n", col.Apply(t.Level, lc), t.Score)
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 54))
	if len(t.Details) > 0 {
		fmt.Fprintf(os.Stderr, "  %-28s %6s %7s %6s\n", "Indicator", "Count", "Weight", "Score")
		fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("-", 54))
		for ind, d := range t.Details {
			fmt.Fprintf(os.Stderr, "  %-28s %6d %5dx %6d\n", ind, d.Count, d.Weight, d.Score)
		}
	} else {
		fmt.Fprintf(os.Stderr, "  No suspicious indicators found.\n")
	}
	fmt.Fprintf(os.Stderr, "  %s\n\n", strings.Repeat("=", 54))
}
