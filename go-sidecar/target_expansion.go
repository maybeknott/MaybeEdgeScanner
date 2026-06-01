package main

import (
	"bufio"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

func loadLines(name string) []string {
	f, err := os.Open(filepath.Clean(name))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return unique(out)
}

func expansionBudget(n int) int {
	if n <= 0 {
		return math.MaxInt
	}
	return n
}

func expandTargets(raw []string, capCount int, maxCIDRHosts int, respectSafety bool) []string {
	capCount = expansionBudget(capCount)
	maxCIDRHosts = expansionBudget(maxCIDRHosts)
	set := make(map[[16]byte]bool)
	var out []string
	for _, item := range raw {
		quotaRemaining := capCount - len(out)
		if quotaRemaining <= 0 {
			break
		}
		for _, expanded := range expandOneStateful(strings.TrimSpace(item), min(maxCIDRHosts, quotaRemaining), respectSafety, set) {
			if expanded != "" {
				addr, err := netip.ParseAddr(expanded)
				if err == nil {
					set[addr.As16()] = true
				}
				out = append(out, expanded)
			}
		}
	}
	return out
}

func expandOneStateful(s string, remaining int, respectSafety bool, seen map[[16]byte]bool) []string {
	if remaining <= 0 || s == "" {
		return nil
	}
	if strings.Contains(s, "-") && !strings.Contains(s, "/") {
		return expandRange(s, remaining, respectSafety, seen)
	}
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil
		}
		if seen[addr.As16()] {
			return nil
		}
		if respectSafety && isReservedOrUnsafe(addr) {
			return nil
		}
		seen[addr.As16()] = true
		return []string{s}
	}
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil
	}
	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	current := prefix.Addr()
	if current.Is4() && hostBits > 1 {
		current = current.Next()
	}
	var out []string
	for current.IsValid() && prefix.Contains(current) && len(out) < remaining {
		if current.Is4() && hostBits > 1 && !prefix.Contains(current.Next()) {
			break
		}
		if seen[current.As16()] {
			current = current.Next()
			continue
		}
		seen[current.As16()] = true
		if !respectSafety || !isReservedOrUnsafe(current) {
			out = append(out, current.String())
		} else {
			metricSafetySkipped.Add(1)
		}
		current = current.Next()
	}
	return out
}

func expandRange(s string, remaining int, respectSafety bool, seen map[[16]byte]bool) []string {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 || remaining <= 0 {
		return nil
	}
	start, err := netip.ParseAddr(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil
	}
	end, err := netip.ParseAddr(strings.TrimSpace(parts[1]))
	if err != nil || start.Is4() != end.Is4() {
		return nil
	}
	if start.Compare(end) > 0 {
		return nil
	}
	var out []string
	for current := start; current.IsValid() && current.Compare(end) <= 0 && len(out) < remaining; current = current.Next() {
		if seen[current.As16()] {
			continue
		}
		seen[current.As16()] = true
		if !respectSafety || !isReservedOrUnsafe(current) {
			out = append(out, current.String())
		} else {
			metricSafetySkipped.Add(1)
		}
	}
	return out
}

func isReservedOrUnsafe(addr netip.Addr) bool {
	for _, prefix := range safetyCIDRPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsUnspecified()
}

func loadSafetyPrefixes() []netip.Prefix {
	lines := append([]string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}, loadLines("assets/do_not_scan_cidrs.txt")...)
	var prefixes []netip.Prefix
	seen := map[string]bool{}
	for _, line := range lines {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		key := prefix.Masked().String()
		if !seen[key] {
			seen[key] = true
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes
}
