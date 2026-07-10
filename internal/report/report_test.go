package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/whoisfrasch/strings/internal"
)

func TestGenerateCreatesFile(t *testing.T) {
	// Create a dummy source file for os.Stat
	srcFile := filepath.Join(t.TempDir(), "test.exe")
	os.WriteFile(srcFile, []byte("fake binary content for testing"), 0644)

	outFile := filepath.Join(t.TempDir(), "report.html")

	results := []internal.StringResult{
		{Value: "http://example.com", Offset: 100, Encoding: "ascii", Categories: []string{"url"}, Entropy: 3.5, EntropyLabel: "normal", Source: "raw", Length: 18},
		{Value: "CreateProcess", Offset: 200, Encoding: "ascii", Categories: []string{"dll_api"}, Entropy: 3.2, EntropyLabel: "normal", SuspiciousGroup: "process", Source: "raw", Length: 13},
	}
	sections := []internal.SectionInfo{
		{Name: ".text", Offset: 0, Size: 1024},
	}

	err := Generate(results, srcFile, sections, outFile)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	html := string(data)
	if !strings.Contains(html, "<!DOCTYPE html>") {
		t.Error("expected HTML doctype")
	}
	if !strings.Contains(html, "bstrings") {
		t.Error("expected bstrings logo in report")
	}
	if !strings.Contains(html, "http://example.com") {
		t.Error("expected URL string in report data")
	}
	if !strings.Contains(html, "CreateProcess") {
		t.Error("expected API string in report data")
	}
}

func TestGenerateEmptyResults(t *testing.T) {
	srcFile := filepath.Join(t.TempDir(), "test.exe")
	os.WriteFile(srcFile, []byte("content"), 0644)

	outFile := filepath.Join(t.TempDir(), "report.html")
	err := Generate(nil, srcFile, nil, outFile)
	if err != nil {
		t.Fatalf("Generate with empty results: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Error("expected valid HTML for empty results")
	}
}

func TestGenerateInvalidSourcePath(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "report.html")
	err := Generate(nil, "/nonexistent/file.exe", nil, outFile)
	if err == nil {
		t.Error("expected error for nonexistent source file")
	}
}

func TestGenerateInvalidOutputPath(t *testing.T) {
	srcFile := filepath.Join(t.TempDir(), "test.exe")
	os.WriteFile(srcFile, []byte("content"), 0644)

	err := Generate(nil, srcFile, nil, "/nonexistent/dir/report.html")
	if err == nil {
		t.Error("expected error for invalid output path")
	}
}

func TestGenerateXSSPrevention(t *testing.T) {
	srcFile := filepath.Join(t.TempDir(), "test.exe")
	os.WriteFile(srcFile, []byte("content"), 0644)
	outFile := filepath.Join(t.TempDir(), "report.html")

	results := []internal.StringResult{
		{Value: "</script><script>alert(1)</script>", Offset: 0, Encoding: "ascii", Categories: []string{"general"}, Source: "raw", Length: 33},
	}

	err := Generate(results, srcFile, nil, outFile)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	html := string(data)
	// The JSON data should have </script> escaped
	if strings.Contains(html, `"</script>`) {
		t.Error("XSS: </script> not escaped in JSON data")
	}
}

func TestTruncateUTF8(t *testing.T) {
	s := "Hello, World!"
	got := truncateUTF8(s, 5)
	if got != "Hello" {
		t.Errorf("truncateUTF8 = %q, want Hello", got)
	}
}

func TestTruncateUTF8Short(t *testing.T) {
	s := "Hi"
	got := truncateUTF8(s, 10)
	if got != "Hi" {
		t.Errorf("expected no truncation, got %q", got)
	}
}

func TestFormatNum(t *testing.T) {
	tests := map[int]string{
		0:       "0",
		999:     "999",
		1000:    "1,000",
		1234567: "1,234,567",
	}
	for n, want := range tests {
		got := formatNum(n)
		if got != want {
			t.Errorf("formatNum(%d) = %q, want %q", n, got, want)
		}
	}
}
