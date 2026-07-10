package parser

import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/whoisfrasch/strings/internal"
)

func ParseSections(filepath string) (sections []internal.SectionInfo) {
	defer func() {
		if r := recover(); r != nil {
			sections = nil
		}
	}()
	sections = parsePE(filepath)
	if len(sections) == 0 {
		sections = parseELF(filepath)
	}
	return sections
}

func FormatType(filepath string) string {
	f, err := os.Open(filepath)
	if err != nil {
		return ""
	}
	defer f.Close()
	magic := make([]byte, 4)
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return ""
	}
	if magic[0] == 'M' && magic[1] == 'Z' {
		return "PE"
	}
	if bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF"
	}
	return ""
}

func GetSectionForOffset(sections []internal.SectionInfo, offset int64) string {
	for _, sec := range sections {
		if offset >= sec.Offset && offset < sec.Offset+sec.Size {
			return sec.Name
		}
	}
	return ""
}

func parsePE(filepath string) []internal.SectionInfo {
	f, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer f.Close()

	magic := make([]byte, 2)
	if n, err := f.Read(magic); err != nil || n < 2 {
		return nil
	}
	if magic[0] != 'M' || magic[1] != 'Z' {
		return nil
	}

	if _, err := f.Seek(0x3C, 0); err != nil {
		return nil
	}
	var peOffset uint32
	if err := binary.Read(f, binary.LittleEndian, &peOffset); err != nil {
		return nil
	}

	// Validate peOffset is within reasonable bounds
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	if int64(peOffset)+4 > info.Size() {
		return nil
	}

	if _, err := f.Seek(int64(peOffset), 0); err != nil {
		return nil
	}
	sig := make([]byte, 4)
	if n, err := f.Read(sig); err != nil || n < 4 {
		return nil
	}
	if !bytes.Equal(sig, []byte{'P', 'E', 0, 0}) {
		return nil
	}

	if _, err := f.Seek(2, 1); err != nil {
		return nil
	}
	var numSections uint16
	if err := binary.Read(f, binary.LittleEndian, &numSections); err != nil {
		return nil
	}
	// Cap numSections to prevent resource exhaustion
	if numSections > 256 {
		return nil
	}

	if _, err := f.Seek(12, 1); err != nil {
		return nil
	}
	var optionalSize uint16
	if err := binary.Read(f, binary.LittleEndian, &optionalSize); err != nil {
		return nil
	}
	if _, err := f.Seek(2, 1); err != nil {
		return nil
	}
	if _, err := f.Seek(int64(optionalSize), 1); err != nil {
		return nil
	}

	var sections []internal.SectionInfo
	for i := 0; i < int(numSections); i++ {
		header := make([]byte, 40)
		n, err := f.Read(header)
		if err != nil || n < 40 {
			break
		}
		nameBytes := bytes.TrimRight(header[:8], "\x00")
		name := string(nameBytes)
		virtualAddr := binary.LittleEndian.Uint32(header[12:16])
		rawSize := binary.LittleEndian.Uint32(header[16:20])
		rawOffset := binary.LittleEndian.Uint32(header[20:24])

		sections = append(sections, internal.SectionInfo{
			Name:           name,
			Offset:         int64(rawOffset),
			Size:           int64(rawSize),
			VirtualAddress: uint64(virtualAddr),
		})
	}
	return sections
}

func parseELF(filepath string) []internal.SectionInfo {
	f, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Read ELF header (64 bytes is enough for both 32-bit and 64-bit)
	header := make([]byte, 64)
	if n, err := f.Read(header); err != nil || n < 64 {
		return nil
	}
	if !bytes.Equal(header[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil
	}

	eiClass := header[4]
	eiData := header[5]
	is64 := eiClass == 2

	var order binary.ByteOrder
	if eiData == 1 {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}

	var shoff uint64
	var shentsize, shnum, shstrndx uint16

	if is64 {
		shoff = order.Uint64(header[0x28:0x30])
		shentsize = order.Uint16(header[0x3A:0x3C])
		shnum = order.Uint16(header[0x3C:0x3E])
		shstrndx = order.Uint16(header[0x3E:0x40])
	} else {
		if len(header) < 0x34 {
			return nil
		}
		shoff = uint64(order.Uint32(header[0x20:0x24]))
		shentsize = order.Uint16(header[0x2E:0x30])
		shnum = order.Uint16(header[0x30:0x32])
		shstrndx = order.Uint16(header[0x32:0x34])
	}

	if shoff == 0 || shnum == 0 || shentsize == 0 {
		return nil
	}
	if shnum > 1024 {
		return nil
	}

	// Read all section headers at once
	shSize := int64(shnum) * int64(shentsize)
	if _, err := f.Seek(int64(shoff), 0); err != nil {
		return nil
	}
	shData := make([]byte, shSize)
	if n, err := f.Read(shData); err != nil || int64(n) < shSize {
		return nil
	}

	// Read string table section header to find strtab location
	strIdx := int64(shstrndx) * int64(shentsize)
	if strIdx+int64(shentsize) > shSize {
		return nil
	}

	var strtabOff, strtabSz uint64
	if is64 {
		if strIdx+40 > shSize {
			return nil
		}
		strtabOff = order.Uint64(shData[strIdx+24 : strIdx+32])
		strtabSz = order.Uint64(shData[strIdx+32 : strIdx+40])
	} else {
		if strIdx+24 > shSize {
			return nil
		}
		strtabOff = uint64(order.Uint32(shData[strIdx+16 : strIdx+20]))
		strtabSz = uint64(order.Uint32(shData[strIdx+20 : strIdx+24]))
	}

	if strtabSz == 0 || strtabSz > 1<<20 {
		return nil
	}

	// Read string table
	if _, err := f.Seek(int64(strtabOff), 0); err != nil {
		return nil
	}
	strtab := make([]byte, strtabSz)
	if n, err := f.Read(strtab); err != nil || uint64(n) < strtabSz {
		return nil
	}

	var sections []internal.SectionInfo
	for i := 0; i < int(shnum); i++ {
		off := int64(i) * int64(shentsize)
		if off+int64(shentsize) > shSize {
			break
		}

		shName := order.Uint32(shData[off : off+4])
		var shAddr, shOff, shSz uint64
		if is64 {
			if off+40 > shSize {
				break
			}
			shAddr = order.Uint64(shData[off+16 : off+24])
			shOff = order.Uint64(shData[off+24 : off+32])
			shSz = order.Uint64(shData[off+32 : off+40])
		} else {
			if off+24 > shSize {
				break
			}
			shAddr = uint64(order.Uint32(shData[off+12 : off+16]))
			shOff = uint64(order.Uint32(shData[off+16 : off+20]))
			shSz = uint64(order.Uint32(shData[off+20 : off+24]))
		}

		name := ""
		if int(shName) < len(strtab) {
			end := bytes.IndexByte(strtab[shName:], 0)
			if end >= 0 && int(shName)+end <= len(strtab) {
				name = string(strtab[shName : int(shName)+end])
			}
		}

		if shSz > 0 && name != "" {
			sections = append(sections, internal.SectionInfo{
				Name:           name,
				Offset:         int64(shOff),
				Size:           int64(shSz),
				VirtualAddress: shAddr,
			})
		}
	}
	return sections
}
