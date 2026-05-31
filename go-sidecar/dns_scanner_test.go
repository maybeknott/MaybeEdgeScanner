package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDNSMessageCapturesAnswersAndFlags(t *testing.T) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Rcode:              dns.RcodeSuccess,
			RecursionAvailable: true,
			Authoritative:      true,
			AuthenticatedData:  true,
			Truncated:          true,
		},
		Answer: []dns.RR{
			&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(93, 184, 216, 34)},
			&dns.AAAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")},
			&dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.example.net."},
			&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 60}, Preference: 10, Mx: "mail.example.com."},
			&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"v=spf1", "include:example.net"}},
			&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1234},
		},
		Extra: []dns.RR{
			&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}},
		},
	}

	parsed := parseDNSMessage(msg)
	if parsed.rcode != dns.RcodeSuccess || !parsed.ra || !parsed.aa || !parsed.ad || !parsed.edns {
		t.Fatalf("flags parsed incorrectly: %+v", parsed)
	}
	if !parsed.truncated || parsed.rawSize <= 0 {
		t.Fatalf("truncation/raw-size parsed incorrectly: %+v", parsed)
	}
	if parsed.ttlMin == nil || *parsed.ttlMin != 60 {
		t.Fatalf("ttl_min=%v, want 60", parsed.ttlMin)
	}
	if len(parsed.ttlRecords) != len(msg.Answer) {
		t.Fatalf("ttl_records=%d, want %d", len(parsed.ttlRecords), len(msg.Answer))
	}
	if !hasString(parsed.cnameChain, "edge.example.net") {
		t.Fatalf("missing cname chain entry: %#v", parsed.cnameChain)
	}
	for _, want := range []string{
		"93.184.216.34",
		"2606:2800:220:1:248:1893:25c8:1946",
		"edge.example.net",
		"10 mail.example.com",
		"v=spf1 include:example.net",
		"ns1.example.com hostmaster.example.com serial=1234",
	} {
		if !hasString(parsed.answers, want) {
			t.Fatalf("missing answer %q in %#v", want, parsed.answers)
		}
	}
}

func TestDNSAttemptFromExchangeClassifiesTruncatedAndFailed(t *testing.T) {
	rtt := 17
	truncated := &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}
	attempt := dnsAttemptFromExchange("udp", truncated, time.Duration(rtt)*time.Millisecond, nil)
	if attempt.Transport != "udp" || attempt.Outcome != "truncated" || !attempt.Truncated || attempt.LatencyMS == nil || *attempt.LatencyMS != int64(rtt) {
		t.Fatalf("truncated attempt parsed incorrectly: %+v", attempt)
	}
	failed := dnsAttemptFromExchange("tcp", nil, 0, context.DeadlineExceeded)
	if failed.Transport != "tcp" || failed.Outcome != "timeout" || failed.ErrorCode != "DNS_TIMEOUT" || failed.Error == "" {
		t.Fatalf("failed attempt parsed incorrectly: %+v", failed)
	}
}

func TestDNSErrorCodeMappingIsStable(t *testing.T) {
	cases := []struct {
		name    string
		rcode   int
		answers int
		want    string
	}{
		{"success with answers", dns.RcodeSuccess, 1, ""},
		{"success no answer", dns.RcodeSuccess, 0, "DNS_NO_ANSWER"},
		{"nxdomain", dns.RcodeNameError, 0, "DNS_NXDOMAIN"},
		{"servfail", dns.RcodeServerFailure, 0, "DNS_SERVFAIL"},
		{"refused", dns.RcodeRefused, 0, "DNS_REFUSED"},
		{"formerr", dns.RcodeFormatError, 0, "DNS_MALFORMED_RESPONSE"},
	}
	for _, tc := range cases {
		if got := dnsRCodeErrorCode(tc.rcode, tc.answers); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := classifyDNSError(context.DeadlineExceeded); got != "DNS_TIMEOUT" {
		t.Fatalf("deadline error code=%q, want DNS_TIMEOUT", got)
	}
}

func TestCollectCNAMEChainDetectsLoop(t *testing.T) {
	chain, loop := collectCNAMEChain(map[string]string{
		"a.example": "b.example",
		"b.example": "c.example",
		"c.example": "a.example",
	})
	if !loop {
		t.Fatalf("expected CNAME loop, got chain=%v", chain)
	}
	for _, want := range []string{"a.example", "b.example", "c.example"} {
		if !hasString(chain, want) {
			t.Fatalf("missing %q in chain %v", want, chain)
		}
	}
}

func TestRunDNSResultMarksCNAMELoopErrorCode(t *testing.T) {
	parsed := parseDNSMessage(&dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "b.example."},
			&dns.CNAME{Hdr: dns.RR_Header{Name: "b.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "a.example."},
		},
	})
	if !parsed.cnameLoop {
		t.Fatalf("expected parsed CNAME loop: %+v", parsed)
	}
	res := dnsResult{Answers: parsed.answers, RCode: parsed.rcode, CNAMELoop: parsed.cnameLoop}
	if res.CNAMELoop {
		res.ErrorCode = "DNS_CNAME_LOOP"
	}
	if res.ErrorCode != "DNS_CNAME_LOOP" {
		t.Fatalf("error_code=%q, want DNS_CNAME_LOOP", res.ErrorCode)
	}
}

func TestDNSTypeCodeUsesMiekgRegistry(t *testing.T) {
	cases := map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA, "MX": dns.TypeMX, "NS": dns.TypeNS, "TXT": dns.TypeTXT, "SOA": dns.TypeSOA, "CNAME": dns.TypeCNAME, "HTTPS": dns.TypeHTTPS}
	for name, want := range cases {
		if got := dnsTypeCode(name); got != want {
			t.Fatalf("dnsTypeCode(%s)=%d, want %d", name, got, want)
		}
	}
	if got := dnsTypeCode("definitely-not-a-record"); got != 0 {
		t.Fatalf("dnsTypeCode returned %d for unsupported type", got)
	}
}

func TestDNSNormalizePreservesExplicitPositiveTimeout(t *testing.T) {
	req := dnsScanRequest{TimeoutMS: 30000, Workers: 2048, Samples: 100}
	req.normalize()
	if req.TimeoutMS != 30000 {
		t.Fatalf("TimeoutMS=%d, want explicit value preserved", req.TimeoutMS)
	}
	if req.Workers != 2048 || req.Samples != 100 {
		t.Fatalf("explicit DNS worker/sample budget not preserved: %+v", req)
	}
}

func TestScanDNSRejectsMalformedBodyWithSanitizedError(t *testing.T) {
	body := bytes.NewBufferString(`{"domains":["example.com"],"resolvers":[`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns", body)
	rec := httptest.NewRecorder()
	scanDNS(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("dns status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
	got := rec.Body.String()
	if !strings.Contains(got, "invalid dns scan request body") || strings.Contains(strings.ToLower(got), "unexpected") {
		t.Fatalf("dns decode error was not sanitized: %q", got)
	}
}

func TestScanDNSRejectsNonPostWithStructuredMethodError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/dns", nil)
	rec := httptest.NewRecorder()
	scanDNS(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("dns status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(rec.Body.String(), `"required_method":"POST"`) {
		t.Fatalf("dns method error was not structured: %q", rec.Body.String())
	}
}

func TestScanDNSAcceptsLargeExplicitWorkloadRequest(t *testing.T) {
	body := bytes.NewBufferString(`{"domains":["example.com"],"resolvers":["1.1.1.1"],"workers":999999}`)
	req := httptest.NewRequest(http.MethodPost, "/api/dns", body)
	rec := httptest.NewRecorder()
	scanDNS(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dns status=%d, want %d body=%q", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"type":"init"`) {
		t.Fatalf("expected init frame, got: %q", rec.Body.String())
	}
}

func hasString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
