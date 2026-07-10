package xor

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sync"

	"github.com/whoisfrasch/strings/internal"
	"github.com/whoisfrasch/strings/internal/categorizer"
	"github.com/whoisfrasch/strings/internal/entropy"
	"github.com/whoisfrasch/strings/internal/parser"
)

var interestingPattern = regexp.MustCompile(`(?i)https?://|\.exe\b|\.dll\b|\.bat\b|\.cmd\b|\.ps1\b|cmd\.exe|powershell|\\windows\\|password|username|admin|HKEY_|BEGIN\s+(?:RSA|CERTIFICATE|PRIVATE)|api[_\-]?key|secret|token|\.onion\b|socket|connect`)

func Bruteforce(data []byte, minLen int, sections []internal.SectionInfo, quiet bool) []internal.StringResult {
	if len(data) == 0 {
		return nil
	}
	if minLen < 1 {
		minLen = 1
	}

	if !quiet {
		fmt.Fprint(os.Stderr, "  xor bruteforce: testing 255 keys...")
	}

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}

	type keyRange struct {
		start, end int
	}

	// Split 255 keys across workers
	keysPerWorker := 255 / workers
	var ranges []keyRange
	for i := 0; i < workers; i++ {
		start := i*keysPerWorker + 1
		end := start + keysPerWorker
		if i == workers-1 {
			end = 256
		}
		ranges = append(ranges, keyRange{start, end})
	}

	type workerResult struct {
		results []internal.StringResult
	}

	patStr := fmt.Sprintf(`[\x20-\x7e\x09]{%d,}`, minLen)
	asciiPat := regexp.MustCompile(patStr)

	var mu sync.Mutex
	var wg sync.WaitGroup
	var allResults []internal.StringResult
	globalSeen := make(map[string]bool)

	for _, kr := range ranges {
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			// Each goroutine gets its own buffer to avoid contention
			xored := make([]byte, len(data))
			var localResults []internal.StringResult
			localSeen := make(map[string]bool)

			for key := start; key < end; key++ {
				k := byte(key)
				for i, b := range data {
					xored[i] = b ^ k
				}

				matches := asciiPat.FindAllIndex(xored, -1)
				for _, loc := range matches {
					s := string(xored[loc[0]:loc[1]])
					if !interestingPattern.MatchString(s) || localSeen[s] {
						continue
					}
					localSeen[s] = true
					offset := int64(loc[0])
					ent := entropy.Calculate(s)

					localResults = append(localResults, internal.StringResult{
						Value:           s,
						Offset:          offset,
						Encoding:        "ascii",
						Section:         parser.GetSectionForOffset(sections, offset),
						Categories:      categorizer.Categorize(s),
						Entropy:         ent,
						EntropyLabel:    entropy.Label(ent),
						SuspiciousGroup: categorizer.GetSuspiciousGroup(s),
						Source:          "xor",
						XorKey:          k,
						Length:          len(s),
					})
				}

				if !quiet && key%32 == 0 {
					fmt.Fprint(os.Stderr, ".")
				}
			}

			// Merge local results into global, dedup
			mu.Lock()
			for _, r := range localResults {
				if !globalSeen[r.Value] {
					globalSeen[r.Value] = true
					allResults = append(allResults, r)
				}
			}
			mu.Unlock()
		}(kr.start, kr.end)
	}

	wg.Wait()

	if !quiet {
		fmt.Fprintln(os.Stderr, " done")
	}
	return allResults
}
