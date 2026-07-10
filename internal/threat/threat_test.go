package threat

import (
	"testing"

	"github.com/whoisfrasch/strings/internal"
)

func TestAssessEmpty(t *testing.T) {
	result := Assess(nil)
	if result.Level != "LOW" {
		t.Errorf("Assess(nil) level = %q, want LOW", result.Level)
	}
	if result.Score != 0 {
		t.Errorf("Assess(nil) score = %d, want 0", result.Score)
	}
}

func TestAssessLow(t *testing.T) {
	results := []internal.StringResult{
		{Value: "hello world", Categories: []string{"general"}, Source: "raw"},
	}
	result := Assess(results)
	if result.Level != "LOW" {
		t.Errorf("Assess low = %q, want LOW", result.Level)
	}
}

func TestAssessMedium(t *testing.T) {
	// Credentials count as 3 each, need at least 4 to hit 10+
	results := []internal.StringResult{
		{Value: "password=secret1", Categories: []string{"credential"}, Source: "raw"},
		{Value: "api_key=abc123", Categories: []string{"credential"}, Source: "raw"},
		{Value: "token=xyz789", Categories: []string{"credential"}, Source: "raw"},
		{Value: "secret=foo", Categories: []string{"credential"}, Source: "raw"},
	}
	result := Assess(results)
	if result.Level != "MEDIUM" {
		t.Errorf("Assess medium level = %q (score %d), want MEDIUM", result.Level, result.Score)
	}
}

func TestAssessHigh(t *testing.T) {
	results := []internal.StringResult{
		// injection: 5 weight x3 = 15
		{Value: "CreateRemoteThread", SuspiciousGroup: "injection", Categories: []string{"dll_api"}, Source: "raw"},
		{Value: "QueueUserAPC", SuspiciousGroup: "injection", Categories: []string{"dll_api"}, Source: "raw"},
		{Value: "NtWriteVirtualMemory", SuspiciousGroup: "injection", Categories: []string{"dll_api"}, Source: "raw"},
		// evasion: 4 weight x2 = 8
		{Value: "IsDebuggerPresent", SuspiciousGroup: "evasion", Categories: []string{"general"}, Source: "raw"},
		{Value: "NtQueryInformationProcess", SuspiciousGroup: "evasion", Categories: []string{"general"}, Source: "raw"},
		// credentials: 3 weight x3 = 9  -> total = 32
		{Value: "password=secret", Categories: []string{"credential"}, Source: "raw"},
		{Value: "api_key=abc", Categories: []string{"credential"}, Source: "raw"},
		{Value: "token=xyz", Categories: []string{"credential"}, Source: "raw"},
	}
	result := Assess(results)
	if result.Score < 30 {
		t.Errorf("Assess high score = %d, want >= 30", result.Score)
	}
	if result.Level != "HIGH" && result.Level != "CRITICAL" {
		t.Errorf("Assess high level = %q, want HIGH or CRITICAL", result.Level)
	}
}

func TestAssessCritical(t *testing.T) {
	var results []internal.StringResult
	// injection: 5 weight x 10 = 50
	for i := 0; i < 10; i++ {
		results = append(results, internal.StringResult{
			Value: "CreateRemoteThread", SuspiciousGroup: "injection",
			Categories: []string{"dll_api"}, Source: "raw",
		})
	}
	// evasion: 4 weight x 5 = 20  -> total = 70
	for i := 0; i < 5; i++ {
		results = append(results, internal.StringResult{
			Value: "IsDebuggerPresent", SuspiciousGroup: "evasion",
			Categories: []string{"general"}, Source: "raw",
		})
	}

	result := Assess(results)
	if result.Level != "CRITICAL" {
		t.Errorf("Assess critical level = %q (score %d), want CRITICAL", result.Level, result.Score)
	}
}

func TestAssessScoreCap(t *testing.T) {
	var results []internal.StringResult
	for i := 0; i < 100; i++ {
		results = append(results, internal.StringResult{
			Value: "CreateRemoteThread", SuspiciousGroup: "injection",
			Categories: []string{"dll_api"}, Source: "raw",
		})
	}
	result := Assess(results)
	if result.Score > 100 {
		t.Errorf("Assess score = %d, should be capped at 100", result.Score)
	}
}

func TestAssessXorBonus(t *testing.T) {
	results := []internal.StringResult{
		{Value: "hidden_string", Categories: []string{"general"}, Source: "xor", XorKey: 0x42},
	}
	result := Assess(results)
	if _, ok := result.Details["xor_obfuscated"]; !ok {
		t.Error("Expected xor_obfuscated in details")
	}
	if result.Details["xor_obfuscated"].Weight != 4 {
		t.Errorf("xor weight = %d, want 4", result.Details["xor_obfuscated"].Weight)
	}
}

func TestAssessBase64Bonus(t *testing.T) {
	results := []internal.StringResult{
		{Value: "decoded_content", Categories: []string{"general"}, Source: "base64"},
	}
	result := Assess(results)
	if _, ok := result.Details["base64_decoded"]; !ok {
		t.Error("Expected base64_decoded in details")
	}
}

func TestAssessHighEntropy(t *testing.T) {
	results := []internal.StringResult{
		{Value: "asdfjkl;qwertyuiop", Categories: []string{"general"}, Source: "raw", Entropy: 5.5},
	}
	result := Assess(results)
	if _, ok := result.Details["high_entropy_strings"]; !ok {
		t.Error("Expected high_entropy_strings in details")
	}
}

func TestAssessLevelBoundaries(t *testing.T) {
	tests := []struct {
		score int
		level string
	}{
		{0, "LOW"},
		{9, "LOW"},
		{10, "MEDIUM"},
		{29, "MEDIUM"},
		{30, "HIGH"},
		{69, "HIGH"},
		{70, "CRITICAL"},
		{100, "CRITICAL"},
	}
	for _, tt := range tests {
		// Create results that produce exact score
		// Use injection (weight 5) to control score precisely
		var results []internal.StringResult
		remaining := tt.score
		for remaining >= 5 {
			results = append(results, internal.StringResult{
				SuspiciousGroup: "injection", Categories: []string{"general"}, Source: "raw",
			})
			remaining -= 5
		}
		// Use file (weight 1) for remaining
		for remaining > 0 {
			results = append(results, internal.StringResult{
				SuspiciousGroup: "file", Categories: []string{"general"}, Source: "raw",
			})
			remaining--
		}
		result := Assess(results)
		if result.Level != tt.level {
			t.Errorf("score %d: level = %q (actual score %d), want %q", tt.score, result.Level, result.Score, tt.level)
		}
	}
}
