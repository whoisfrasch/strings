package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/whoisfrasch/strings/internal"
)

func TestParseSectionsInvalidFile(t *testing.T) {
	sections := ParseSections("/nonexistent/file")
	if sections != nil {
		t.Error("expected nil for nonexistent file")
	}
}

func TestParseSectionsEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.bin")
	os.WriteFile(tmp, []byte{}, 0644)
	sections := ParseSections(tmp)
	if len(sections) != 0 {
		t.Errorf("expected no sections for empty file, got %d", len(sections))
	}
}

func TestParseSectionsNotBinary(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "text.txt")
	os.WriteFile(tmp, []byte("just a text file with some content"), 0644)
	sections := ParseSections(tmp)
	if len(sections) != 0 {
		t.Errorf("expected no sections for text file, got %d", len(sections))
	}
}

func TestParseSectionsBadMZHeader(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad_pe.bin")
	data := make([]byte, 256)
	data[0] = 'M'
	data[1] = 'Z'
	// PE offset pointing beyond file
	data[0x3C] = 0xFF
	data[0x3D] = 0xFF
	os.WriteFile(tmp, data, 0644)
	sections := ParseSections(tmp)
	if len(sections) != 0 {
		t.Errorf("expected no sections for bad PE header, got %d", len(sections))
	}
}

func TestParseSectionsBadELFHeader(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad_elf.bin")
	data := make([]byte, 256)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	// Rest is zeros — invalid section headers
	os.WriteFile(tmp, data, 0644)
	sections := ParseSections(tmp)
	if len(sections) != 0 {
		t.Errorf("expected no sections for bad ELF header, got %d", len(sections))
	}
}

func TestFormatTypeEmpty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.bin")
	os.WriteFile(tmp, []byte{}, 0644)
	ft := FormatType(tmp)
	if ft != "" {
		t.Errorf("expected empty format type, got %q", ft)
	}
}

func TestFormatTypePE(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "pe.bin")
	data := make([]byte, 64)
	data[0] = 'M'
	data[1] = 'Z'
	os.WriteFile(tmp, data, 0644)
	ft := FormatType(tmp)
	if ft != "PE" {
		t.Errorf("expected PE, got %q", ft)
	}
}

func TestFormatTypeELF(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "elf.bin")
	data := make([]byte, 64)
	data[0] = 0x7f
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	os.WriteFile(tmp, data, 0644)
	ft := FormatType(tmp)
	if ft != "ELF" {
		t.Errorf("expected ELF, got %q", ft)
	}
}

func TestFormatTypeNotFound(t *testing.T) {
	ft := FormatType("/nonexistent")
	if ft != "" {
		t.Errorf("expected empty, got %q", ft)
	}
}

func TestGetSectionForOffset(t *testing.T) {
	sections := []internal.SectionInfo{
		{Name: ".text", Offset: 0, Size: 100},
		{Name: ".data", Offset: 100, Size: 200},
	}
	if s := GetSectionForOffset(sections, 50); s != ".text" {
		t.Errorf("offset 50: got %q, want .text", s)
	}
	if s := GetSectionForOffset(sections, 150); s != ".data" {
		t.Errorf("offset 150: got %q, want .data", s)
	}
	if s := GetSectionForOffset(sections, 400); s != "" {
		t.Errorf("offset 400: got %q, want empty", s)
	}
	if s := GetSectionForOffset(nil, 0); s != "" {
		t.Errorf("nil sections: got %q, want empty", s)
	}
}
