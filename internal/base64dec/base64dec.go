package base64dec

import (
	"encoding/base64"
	"regexp"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/categorizer"
	"github.com/whoisfrasch/strings/internal/entropy"
	"github.com/whoisfrasch/strings/internal/parser"
)

var b64Pattern = regexp.MustCompile(`(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)

func Extract(data []byte, minLen int, sections []internal.SectionInfo) []internal.StringResult {
	if minLen < 1 {
		minLen = 1
	}
	matches := b64Pattern.FindAllIndex(data, -1)
	results := make([]internal.StringResult, 0, len(matches)/4)

	for _, loc := range matches {
		raw := data[loc[0]:loc[1]]

		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			// Try with RawStdEncoding for unpadded base64
			decoded, err = base64.RawStdEncoding.DecodeString(string(raw))
			if err != nil {
				continue
			}
		}

		if len(decoded) == 0 || len(decoded) < minLen {
			continue
		}

		printable := 0
		for _, b := range decoded {
			if (b >= 0x20 && b <= 0x7e) || b == 0x09 || b == 0x0a || b == 0x0d {
				printable++
			}
		}

		if float64(printable)/float64(len(decoded)) < 0.7 {
			continue
		}

		s := string(decoded)
		ent := entropy.Calculate(s)
		offset := int64(loc[0])

		results = append(results, internal.StringResult{
			Value:           s,
			Offset:          offset,
			Encoding:        "base64",
			Section:         parser.GetSectionForOffset(sections, offset),
			Categories:      categorizer.Categorize(s),
			Entropy:         ent,
			EntropyLabel:    entropy.Label(ent),
			SuspiciousGroup: categorizer.GetSuspiciousGroup(s),
			Source:          "base64",
			Length:          len(s),
		})
	}
	return results
}
