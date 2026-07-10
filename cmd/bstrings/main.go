package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/base64dec"
	"github.com/whoisfrasch/strings/internal/categorizer"
	"github.com/whoisfrasch/strings/internal/color"
	"github.com/whoisfrasch/strings/internal/diff"
	"github.com/whoisfrasch/strings/internal/output"
	"github.com/whoisfrasch/strings/internal/parser"
	"github.com/whoisfrasch/strings/internal/report"
	"github.com/whoisfrasch/strings/internal/scanner"
	"github.com/whoisfrasch/strings/internal/xor"
)

var (
	minLength  = flag.Int("n", 4, "minimum string length")
	encoding   = flag.String("e", "ascii", "encoding (ascii, utf-8, utf-16-le, utf-16-be)")
	allEnc     = flag.Bool("a", false, "scan all encodings")
	base64Flag = flag.Bool("base64", false, "decode base64 strings")
	xorFlag    = flag.Bool("xor", false, "xor single-byte bruteforce")
	only       = flag.String("only", "", "filter by category (urls,apis,passwords,network,paths,crypto,hashes,emails,suspicious)")
	diffFile   = flag.String("diff", "", "compare with another file")
	filter     = flag.String("f", "", "regex filter")
	ignoreCase = flag.Bool("i", false, "case-insensitive filter")
	dedup      = flag.Bool("d", false, "remove duplicates")
	offsetFlag = flag.Bool("o", false, "show offsets")
	context    = flag.Bool("context", false, "show hex context")
	jsonOut    = flag.Bool("json", false, "json output")
	csvOut     = flag.Bool("csv", false, "csv output")
	stats      = flag.Bool("stats", false, "show statistics")
	threatFlag = flag.Bool("threat", false, "threat assessment")
	reportFile = flag.String("report", "", "generate html report")
	colorFlag  = flag.Bool("color", false, "colored output")
	quiet      = flag.Bool("q", false, "quiet mode")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "bstrings - advanced binary string extractor\n\n")
		fmt.Fprintf(os.Stderr, "usage: bstrings <file> [options]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\npresets for --only:\n")
		fmt.Fprintf(os.Stderr, "  urls, apis, passwords, network, paths, crypto, hashes, emails, suspicious\n")
		fmt.Fprintf(os.Stderr, "\nexamples:\n")
		fmt.Fprintf(os.Stderr, "  bstrings file.exe -a --base64 --xor --report report.html\n")
		fmt.Fprintf(os.Stderr, "  bstrings file.exe --only urls,passwords -a --color\n")
		fmt.Fprintf(os.Stderr, "  bstrings file.exe --only suspicious --threat --color\n")
		fmt.Fprintf(os.Stderr, "  bstrings app_v1.exe --diff app_v2.exe --color\n")
	}

	files, flagArgs := parseArgs(os.Args[1:])
	flag.CommandLine.Parse(flagArgs)

	if len(files) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	if *minLength < 1 {
		fmt.Fprintf(os.Stderr, "  error: minimum string length (-n) must be >= 1\n")
		os.Exit(1)
	}

	col := &color.Colorizer{Enabled: *colorFlag}

	if *diffFile != "" {
		handleDiff(files[0], *diffFile, col)
		return
	}

	cfg := &output.Config{
		Color:   col,
		Offset:  *offsetFlag,
		Context: *context,
		Quiet:   *quiet,
	}

	for _, fp := range files {
		results, sections := processFile(fp)
		if results == nil {
			continue
		}
		outputResults(results, sections, fp, cfg)
	}
}

func parseArgs(args []string) (files, flagArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				needsVal := a == "-n" || a == "--n" || a == "-e" || a == "--e" || a == "-f" || a == "--f" ||
					a == "--only" || a == "--diff" || a == "--report" ||
					a == "-only" || a == "-diff" || a == "-report" || a == "-filter" || a == "--filter"
				if needsVal {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
		} else {
			files = append(files, a)
		}
	}
	return
}

func processFile(fp string) ([]internal.StringResult, []internal.SectionInfo) {
	info, err := os.Stat(fp)
	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  error: %s not found\n", fp)
		}
		return nil, nil
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "  scanning: %s (%s)\n", fp, internal.FormatSize(info.Size()))
	}

	sections := parser.ParseSections(fp)
	if len(sections) > 0 && !*quiet {
		fmt.Fprintf(os.Stderr, "  format: %s | %d sections\n", parser.FormatType(fp), len(sections))
	}

	encodings := []string{*encoding}
	if *allEnc {
		encodings = []string{"ascii", "utf-8", "utf-16-le", "utf-16-be"}
	}

	filterPat := compileFilter()

	onlyCats := parseOnlyFilter()

	data, cleanup, err := scanner.LoadFile(fp)
	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  error loading file: %v\n", err)
		}
		return nil, nil
	}
	defer cleanup()

	if !*quiet {
		fmt.Fprintf(os.Stderr, "  encodings: %s\n", strings.Join(encodings, ", "))
	}

	rawResults := scanner.ExtractMulti(data, *minLength, encodings, sections, filterPat, *context)

	var allResults []internal.StringResult
	seen := make(map[string]bool)
	for _, r := range rawResults {
		if *dedup && seen[r.Value] {
			continue
		}
		if onlyCats != nil && !matchOnly(r, onlyCats) {
			continue
		}
		seen[r.Value] = true
		allResults = append(allResults, r)
	}

	if *base64Flag {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "  base64 decoding...\n")
		}
		for _, r := range base64dec.Extract(data, *minLength, sections) {
			if *dedup && seen[r.Value] {
				continue
			}
			seen[r.Value] = true
			allResults = append(allResults, r)
		}
	}

	if *xorFlag {
		ml := *minLength
		if ml < 6 {
			ml = 6
		}
		for _, r := range xor.Bruteforce(data, ml, sections, *quiet) {
			if *dedup && seen[r.Value] {
				continue
			}
			seen[r.Value] = true
			allResults = append(allResults, r)
		}
	}

	return allResults, sections
}

func compileFilter() *regexp.Regexp {
	if *filter == "" {
		return nil
	}
	flags := ""
	if *ignoreCase {
		flags = "(?i)"
	}
	pat, err := regexp.Compile(flags + *filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: invalid regex %q: %v\n", *filter, err)
		os.Exit(1)
	}
	return pat
}

func parseOnlyFilter() map[string]bool {
	if *only == "" {
		return nil
	}
	onlyCats := make(map[string]bool)
	for _, preset := range strings.Split(*only, ",") {
		preset = strings.TrimSpace(strings.ToLower(preset))
		if cats, ok := categorizer.OnlyPresets[preset]; ok {
			for _, c := range cats {
				onlyCats[c] = true
			}
		} else {
			onlyCats[preset] = true
		}
	}
	return onlyCats
}

func matchOnly(r internal.StringResult, onlyCats map[string]bool) bool {
	for _, c := range r.Categories {
		if onlyCats[c] {
			return true
		}
	}
	if onlyCats["dll_api"] && r.SuspiciousGroup != "" {
		return true
	}
	return false
}

func outputResults(results []internal.StringResult, sections []internal.SectionInfo, fp string, cfg *output.Config) {
	if *reportFile != "" {
		if err := report.Generate(results, fp, sections, *reportFile); err != nil {
			fmt.Fprintf(os.Stderr, "  error generating report: %v\n", err)
		} else if !*quiet {
			fmt.Fprintf(os.Stderr, "  report: %s\n", *reportFile)
		}
	} else if *jsonOut {
		output.PrintJSON(results, fp)
	} else if *csvOut {
		output.PrintCSV(results)
	} else {
		output.PrintText(results, cfg)
	}

	if *stats {
		output.PrintStats(results, fp, sections, cfg.Color)
	}
	if *threatFlag {
		output.PrintThreat(results, cfg.Color)
	}
}

func handleDiff(fileA, fileB string, col *color.Colorizer) {
	resA, _ := processFile(fileA)
	resB, _ := processFile(fileB)
	if resA == nil || resB == nil {
		return
	}
	d := diff.Compare(resA, resB)
	diff.Print(d, fileA, fileB, col.Enabled)
}
