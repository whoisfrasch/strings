package diff

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/whoisfrasch/strings/internal"
)

type DiffResult struct {
	OnlyA  []string
	OnlyB  []string
	Common int
}

func Compare(a, b []internal.StringResult) DiffResult {
	setA := make(map[string]bool)
	setB := make(map[string]bool)
	for _, r := range a {
		setA[r.Value] = true
	}
	for _, r := range b {
		setB[r.Value] = true
	}

	var onlyA, onlyB []string
	common := 0

	for s := range setA {
		if setB[s] {
			common++
		} else {
			onlyA = append(onlyA, s)
		}
	}
	for s := range setB {
		if !setA[s] {
			onlyB = append(onlyB, s)
		}
	}

	sort.Strings(onlyA)
	sort.Strings(onlyB)

	return DiffResult{OnlyA: onlyA, OnlyB: onlyB, Common: common}
}

func Print(d DiffResult, fileA, fileB string, color bool) {
	nameA := filepath.Base(fileA)
	nameB := filepath.Base(fileB)

	red := func(s string) string { return s }
	green := func(s string) string { return s }
	bold := func(s string) string { return s }
	if color {
		red = func(s string) string { return "\033[91m" + s + "\033[0m" }
		green = func(s string) string { return "\033[92m" + s + "\033[0m" }
		bold = func(s string) string { return "\033[1m" + s + "\033[0m" }
	}

	fmt.Println()
	fmt.Println("  " + bold("DIFF RESULTS"))
	fmt.Println("  ======================================================")
	fmt.Printf("  Common:               %8d\n", d.Common)
	fmt.Printf("  Only in %-12s: %6d\n", nameA, len(d.OnlyA))
	fmt.Printf("  Only in %-12s: %6d\n", nameB, len(d.OnlyB))
	fmt.Println("  ======================================================")

	if len(d.OnlyA) > 0 {
		fmt.Printf("\n  %s\n", red("--- Only in "+nameA+" ---"))
		for _, s := range d.OnlyA {
			fmt.Printf("  %s %s\n", red("-"), s)
		}
	}
	if len(d.OnlyB) > 0 {
		fmt.Printf("\n  %s\n", green("+++ Only in "+nameB+" +++"))
		for _, s := range d.OnlyB {
			fmt.Printf("  %s %s\n", green("+"), s)
		}
	}
}
