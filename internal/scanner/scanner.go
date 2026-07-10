package scanner

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"regexp"
	"sync"
	"syscall"
	"unicode/utf16"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/categorizer"
	"github.com/whoisfrasch/strings/internal/entropy"
	"github.com/whoisfrasch/strings/internal/parser"
)

var encodingPatterns = map[string]string{
	"ascii":     `[\x20-\x7e\x09]{%d,}`,
	"utf-8":     `(?:[\x20-\x7e\x09]|[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]|[\xe1-\xec][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]|[\xee-\xef][\x80-\xbf]{2}){%d,}`,
	"utf-16-le": `(?:[\x20-\x7e\x09]\x00){%d,}`,
	"utf-16-be": `(?:\x00[\x20-\x7e\x09]){%d,}`,
}

var (
	regexCacheMu sync.Mutex
	regexCache   = make(map[string]*regexp.Regexp)
)

func getEncodingRegex(enc string, minLen int) (*regexp.Regexp, bool) {
	patFmt, ok := encodingPatterns[enc]
	if !ok {
		return nil, false
	}
	key := fmt.Sprintf("%s:%d", enc, minLen)
	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()
	if pat, ok := regexCache[key]; ok {
		return pat, true
	}
	patStr := fmt.Sprintf(patFmt, minLen)
	pat := regexp.MustCompile(patStr)
	regexCache[key] = pat
	return pat, true
}

func LoadFile(filepath string) ([]byte, func(), error) {
	noop := func() {}

	info, err := os.Stat(filepath)
	if err != nil {
		return nil, noop, err
	}

	if info.Size() == 0 {
		return []byte{}, noop, nil
	}

	if info.Size() < 1_000_000 {
		data, err := os.ReadFile(filepath)
		return data, noop, err
	}

	// Guard against int overflow on 32-bit systems
	if info.Size() > int64(math.MaxInt) {
		data, err := os.ReadFile(filepath)
		return data, noop, err
	}

	f, err := os.Open(filepath)
	if err != nil {
		return nil, noop, err
	}
	defer f.Close()

	data, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		data, err := os.ReadFile(filepath)
		return data, noop, err
	}
	cleanup := func() {
		syscall.Munmap(data)
	}
	return data, cleanup, nil
}

// ExtractMulti scans data with multiple encodings in parallel, returning
// deduplicated results. This is faster than calling Extract sequentially
// for each encoding.
func ExtractMulti(data []byte, minLen int, encodings []string, sections []internal.SectionInfo, filterPat *regexp.Regexp, showContext bool) []internal.StringResult {
	if len(encodings) == 1 {
		return Extract(data, minLen, encodings[0], sections, filterPat, showContext)
	}

	type encResult struct {
		results []internal.StringResult
	}

	ch := make(chan encResult, len(encodings))
	for _, enc := range encodings {
		go func(e string) {
			ch <- encResult{Extract(data, minLen, e, sections, filterPat, showContext)}
		}(enc)
	}

	var allResults []internal.StringResult
	for range encodings {
		er := <-ch
		allResults = append(allResults, er.results...)
	}
	return allResults
}

func Extract(data []byte, minLen int, enc string, sections []internal.SectionInfo, filterPat *regexp.Regexp, showContext bool) []internal.StringResult {
	pat, ok := getEncodingRegex(enc, minLen)
	if !ok {
		return nil
	}

	matches := pat.FindAllIndex(data, -1)
	results := make([]internal.StringResult, 0, len(matches))

	for _, loc := range matches {
		raw := data[loc[0]:loc[1]]
		s := decodeBytes(raw, enc)
		offset := int64(loc[0])

		if filterPat != nil && !filterPat.MatchString(s) {
			continue
		}

		ent := entropy.Calculate(s)
		cats := categorizer.Categorize(s)
		section := parser.GetSectionForOffset(sections, offset)
		apiGroup := categorizer.GetSuspiciousGroup(s)

		r := internal.StringResult{
			Value:           s,
			Offset:          offset,
			Encoding:        enc,
			Section:         section,
			Categories:      cats,
			Entropy:         ent,
			EntropyLabel:    entropy.Label(ent),
			SuspiciousGroup: apiGroup,
			Source:          "raw",
			Length:          len(s),
		}

		if showContext {
			r.HexBefore, r.HexAfter = hexContext(data, loc[0], loc[1]-loc[0], 16)
		}

		results = append(results, r)
	}
	return results
}

func decodeBytes(raw []byte, enc string) string {
	switch enc {
	case "ascii", "utf-8":
		return string(raw)
	case "utf-16-le":
		if len(raw) < 2 {
			return ""
		}
		u16s := make([]uint16, len(raw)/2)
		for i := range u16s {
			u16s[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		}
		return string(utf16.Decode(u16s))
	case "utf-16-be":
		if len(raw) < 2 {
			return ""
		}
		u16s := make([]uint16, len(raw)/2)
		for i := range u16s {
			u16s[i] = binary.BigEndian.Uint16(raw[i*2 : i*2+2])
		}
		return string(utf16.Decode(u16s))
	}
	return string(raw)
}

func hexContext(data []byte, offset, length, ctx int) (string, string) {
	start := offset - ctx
	if start < 0 {
		start = 0
	}
	before := data[start:offset]

	end := offset + length + ctx
	if end > len(data) {
		end = len(data)
	}
	afterStart := offset + length
	if afterStart > len(data) {
		afterStart = len(data)
	}
	after := data[afterStart:end]

	return formatHex(before), formatHex(after)
}

// formatHex converts bytes to space-separated hex string with pre-allocated buffer.
func formatHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Pre-allocate: each byte = 2 hex chars + 1 space (except last)
	buf := make([]byte, 0, len(b)*3-1)
	hexChars := "0123456789ABCDEF"
	for i, v := range b {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, hexChars[v>>4], hexChars[v&0x0f])
	}
	return string(buf)
}
