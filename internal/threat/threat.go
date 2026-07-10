package threat

import "github.com/whoisfrasch/strings/internal"

var weights = map[string]int{
	"process": 2, "injection": 5, "registry": 1, "network": 2,
	"file": 1, "crypto": 2, "evasion": 4, "privilege": 4, "service": 3,
}

func Assess(results []internal.StringResult) internal.ThreatResult {
	details := make(map[string]internal.ThreatDetails)
	score := 0

	// Single pass over results
	apiCounts := make(map[string]int)
	highEntropy := 0
	credCount := 0
	xorCount := 0
	b64Count := 0

	for _, r := range results {
		if r.SuspiciousGroup != "" {
			apiCounts[r.SuspiciousGroup]++
		}
		if r.Entropy >= 5.0 {
			highEntropy++
		}
		if r.Source == "xor" {
			xorCount++
		}
		if r.Source == "base64" {
			b64Count++
		}
		for _, c := range r.Categories {
			if c == "credential" || c == "basic_auth" || c == "bearer_token" {
				credCount++
				break
			}
		}
	}

	for group, count := range apiCounts {
		w := weights[group]
		if w == 0 {
			w = 1
		}
		s := count * w
		score += s
		details[group] = internal.ThreatDetails{Count: count, Weight: w, Score: s}
	}

	if highEntropy > 0 {
		s := highEntropy * 2
		score += s
		details["high_entropy_strings"] = internal.ThreatDetails{Count: highEntropy, Weight: 2, Score: s}
	}

	if credCount > 0 {
		s := credCount * 3
		score += s
		details["credentials"] = internal.ThreatDetails{Count: credCount, Weight: 3, Score: s}
	}

	if xorCount > 0 {
		s := xorCount * 4
		score += s
		details["xor_obfuscated"] = internal.ThreatDetails{Count: xorCount, Weight: 4, Score: s}
	}

	if b64Count > 0 {
		score += b64Count
		details["base64_decoded"] = internal.ThreatDetails{Count: b64Count, Weight: 1, Score: b64Count}
	}

	// Cap score at 100 to keep levels meaningful
	if score > 100 {
		score = 100
	}

	level := "LOW"
	switch {
	case score >= 70:
		level = "CRITICAL"
	case score >= 30:
		level = "HIGH"
	case score >= 10:
		level = "MEDIUM"
	}

	return internal.ThreatResult{Level: level, Score: score, Details: details}
}
