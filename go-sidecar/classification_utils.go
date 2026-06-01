package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"

	tls "github.com/refraction-networking/utls"
)

func score(r result) int {
	s := 0
	if r.TCP {
		s += 20
	}
	if r.TLS {
		s += 35
	}
	if r.HTTP {
		s += 35
	}
	if strings.EqualFold(r.TLSVersion, "TLS1.3") {
		s += 8
	}
	if strings.EqualFold(r.ALPN, "h2") {
		s += 7
	}
	if r.HTTP3Hint {
		s += 6
	}
	if r.NetworkClassification != "" && r.NetworkClassification != "unknown" {
		s += 8
	}
	if r.TLSFingerprint != "" {
		s += 3
	}
	if r.LatencyMS > 0 {
		s += max(0, 45-int(math.Log1p(float64(r.LatencyMS))*8))
	}
	if r.Error != "" {
		s -= 8
	}
	if s < 0 {
		return 0
	}
	return s
}

func classifyNetworkError(err error, phase string) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	prefix := "SCAN"
	switch phase {
	case "dns":
		prefix = "DNS"
	case "tcp":
		prefix = "TCP_CONNECT"
	case "tls":
		prefix = "TLS_HANDSHAKE"
	case "http":
		prefix = "HTTP"
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(lower, "timeout"):
		return prefix + "_TIMEOUT"
	case strings.Contains(lower, "reset"):
		return prefix + "_RESET"
	case strings.Contains(lower, "refused"):
		return prefix + "_REFUSED"
	default:
		return prefix + "_FAILED"
	}
}

func detectNetworkClassification(ip, sni, cert string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		if classification, ok := networkClassificationIndex.MatchLongestPrefix(addr); ok {
			return classification
		}
	}
	host := strings.ToLower(sni + " " + cert)
	switch {
	case strings.Contains(host, "cloudflare"):
		return "cloudflare"
	case strings.Contains(host, "github") || strings.Contains(host, "fastly"):
		return "fastly"
	case strings.Contains(host, "akamai"):
		return "akamai"
	case strings.Contains(host, "cloudfront") || strings.Contains(host, "amazon"):
		return "cloudfront"
	default:
		return "unknown"
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
