package main

import (
	"context"
	"math/rand"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

func trackAdaptiveBackoff(recentErrors []string, ratePerSecond int) {
	if ratePerSecond <= 0 || len(recentErrors) < 24 {
		globalBackoffNS.Store(0)
		return
	}
	noisy := 0
	for _, errText := range recentErrors {
		lower := strings.ToLower(errText)
		if strings.Contains(lower, "timeout") || strings.Contains(lower, "reset") {
			noisy++
		}
	}
	if noisy*100/len(recentErrors) >= 40 {
		metricBackoffEvents.Add(1)
		delay := time.Duration(min(2000, 250+noisy*25)) * time.Millisecond
		globalBackoffNS.Store(delay.Nanoseconds())
	}
}

func scanWarnings(req scanRequest, targets []string) []string {
	var warnings []string
	if req.BatchSize > resultBufferSize(req.BatchSize) {
		warnings = append(warnings, "Batch size is preserved; the internal result channel buffer is bounded to protect process memory.")
	}
	if req.RatePerSecond == 0 {
		warnings = append(warnings, "No rate limit configured: scans may look bursty to IDS/IPS systems.")
	}
	unsafe := 0
	for _, target := range targets {
		if addr, err := netip.ParseAddr(target); err == nil {
			if isReservedOrUnsafe(addr) {
				unsafe++
				if unsafe >= 5 {
					break
				}
			}
		}
	}
	if unsafe > 0 {
		warnings = append(warnings, "Reserved/private/special-use addresses were present and are skipped when safety mode is enabled.")
	}
	return warnings
}

func resultBufferSize(batchSize int) int {
	if batchSize <= 0 {
		return 1
	}
	return min(batchSize, 1048576)
}

func shuffleStrings(xs []string) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(xs), func(i, j int) { xs[i], xs[j] = xs[j], xs[i] })
}

func newRateLimiter(ratePerSecond int) *rate.Limiter {
	if ratePerSecond <= 0 {
		return nil
	}
	burst := max(1, min(ratePerSecond, 512))
	return rate.NewLimiter(rate.Limit(ratePerSecond), burst)
}

func waitRate(ctx context.Context, limiter *rate.Limiter, jitterMS int) {
	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return
		}
	}
	if jitterMS > 0 {
		delay := time.Duration(rand.Intn(jitterMS+1)) * time.Millisecond
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}

func unique(xs []string) []string {
	set := make(map[string]bool)
	var out []string
	for _, x := range xs {
		for _, part := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || r == '\r' || r == '\n' || r == '\t' || r == ' ' }) {
			part = strings.TrimSpace(part)
			if part != "" && !set[part] {
				set[part] = true
				out = append(out, part)
			}
		}
	}
	sort.Strings(out)
	return out
}

func flush(f http.Flusher) {
	if f != nil {
		f.Flush()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func atoi(s string, fallback int) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}
