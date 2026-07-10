package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whoisfrasch/strings/internal"
)

func TestExtractASCII(t *testing.T) {
	data := []byte("hello world\x00\x01\x02test string here")
	results := Extract(data, 4, "ascii", nil, nil, false)
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	found := false
	for _, r := range results {
		if r.Value == "hello world" {
			found = true
			if r.Encoding != "ascii" {
				t.Errorf("encoding = %q, want ascii", r.Encoding)
			}
			if r.Source != "raw" {
				t.Errorf("source = %q, want raw", r.Source)
			}
		}
	}
	if !found {
		t.Error("expected 'hello world' in results")
	}
}

func TestExtractMinLength(t *testing.T) {
	data := []byte("ab\x00longstring\x00xy")
	results4 := Extract(data, 4, "ascii", nil, nil, false)
	results2 := Extract(data, 2, "ascii", nil, nil, false)
	if len(results4) >= len(results2) {
		t.Errorf("shorter min length should produce more results: got %d vs %d", len(results2), len(results4))
	}
}

func TestExtractUTF16LE(t *testing.T) {
	// "ABCD" in UTF-16-LE
	data := []byte{'A', 0, 'B', 0, 'C', 0, 'D', 0}
	results := Extract(data, 4, "utf-16-le", nil, nil, false)
	if len(results) == 0 {
		t.Fatal("expected UTF-16-LE results")
	}
	if results[0].Value != "ABCD" {
		t.Errorf("value = %q, want ABCD", results[0].Value)
	}
}

func TestExtractUTF16BE(t *testing.T) {
	// "ABCD" in UTF-16-BE
	data := []byte{0, 'A', 0, 'B', 0, 'C', 0, 'D'}
	results := Extract(data, 4, "utf-16-be", nil, nil, false)
	if len(results) == 0 {
		t.Fatal("expected UTF-16-BE results")
	}
	if results[0].Value != "ABCD" {
		t.Errorf("value = %q, want ABCD", results[0].Value)
	}
}

func TestExtractWithSections(t *testing.T) {
	data := []byte("test string in section")
	sections := []internal.SectionInfo{
		{Name: ".text", Offset: 0, Size: 100},
	}
	results := Extract(data, 4, "ascii", sections, nil, false)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].Section != ".text" {
		t.Errorf("section = %q, want .text", results[0].Section)
	}
}

func TestExtractWithContext(t *testing.T) {
	data := []byte("\x01\x02\x03hello world\x04\x05\x06")
	results := Extract(data, 4, "ascii", nil, nil, true)
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].HexBefore == "" {
		t.Error("expected hex context before")
	}
	if results[0].HexAfter == "" {
		t.Error("expected hex context after")
	}
}

func TestExtractMultiEncodings(t *testing.T) {
	// ASCII string + UTF-16-LE string
	ascii := []byte("hello world\x00\x00\x00")
	utf16 := []byte{'T', 0, 'E', 0, 'S', 0, 'T', 0}
	data := append(ascii, utf16...)
	results := ExtractMulti(data, 4, []string{"ascii", "utf-16-le"}, nil, nil, false)
	if len(results) < 2 {
		t.Errorf("expected at least 2 results from multi encoding, got %d", len(results))
	}
}

func TestExtractMultiSingleEncoding(t *testing.T) {
	data := []byte("test string")
	results := ExtractMulti(data, 4, []string{"ascii"}, nil, nil, false)
	if len(results) == 0 {
		t.Fatal("expected results from single encoding ExtractMulti")
	}
}

func TestExtractInvalidEncoding(t *testing.T) {
	data := []byte("test")
	results := Extract(data, 4, "invalid-enc", nil, nil, false)
	if results != nil {
		t.Errorf("expected nil for invalid encoding, got %v", results)
	}
}

func TestExtractEmpty(t *testing.T) {
	results := Extract(nil, 4, "ascii", nil, nil, false)
	if len(results) != 0 {
		t.Errorf("expected no results for empty data, got %d", len(results))
	}
}

func TestLoadFileSmall(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.bin")
	os.WriteFile(tmp, []byte("hello world test file content"), 0644)
	data, cleanup, err := LoadFile(tmp)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	defer cleanup()
	if len(data) == 0 {
		t.Error("expected data from LoadFile")
	}
}

func TestLoadFileEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.bin")
	os.WriteFile(tmp, []byte{}, 0644)
	data, cleanup, err := LoadFile(tmp)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	defer cleanup()
	if len(data) != 0 {
		t.Errorf("expected empty data, got %d bytes", len(data))
	}
}

func TestLoadFileNotFound(t *testing.T) {
	_, _, err := LoadFile("/nonexistent/file/path")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestFormatHex(t *testing.T) {
	got := formatHex([]byte{0xAB, 0xCD, 0x01})
	want := "AB CD 01"
	if got != want {
		t.Errorf("formatHex = %q, want %q", got, want)
	}
}

func TestFormatHexEmpty(t *testing.T) {
	got := formatHex(nil)
	if got != "" {
		t.Errorf("formatHex(nil) = %q, want empty", got)
	}
}

func TestDecodeBytesASCII(t *testing.T) {
	got := decodeBytes([]byte("hello"), "ascii")
	if got != "hello" {
		t.Errorf("decodeBytes ascii = %q", got)
	}
}

func TestDecodeBytesUTF16LEShort(t *testing.T) {
	got := decodeBytes([]byte{0x41}, "utf-16-le")
	if got != "" {
		t.Errorf("expected empty for short utf-16-le, got %q", got)
	}
}
