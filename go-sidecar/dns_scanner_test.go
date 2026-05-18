package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestParseDNSMessageCapturesAnswersAndFlags(t *testing.T) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Rcode:              dns.RcodeSuccess,
			RecursionAvailable: true,
			Authoritative:      true,
			AuthenticatedData:  true,
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

func hasString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
