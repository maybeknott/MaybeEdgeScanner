package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type dnsScanRequest struct {
	Resolvers     []string `json:"resolvers"`
	Domains       []string `json:"domains"`
	QTypes        []string `json:"qtypes"`
	TimeoutMS     int      `json:"timeout_ms"`
	Workers       int      `json:"workers"`
	Samples       int      `json:"samples"`
	RatePerSecond int      `json:"rate_per_second"`
	JitterMS      int      `json:"jitter_ms"`
}

type dnsResult struct {
	Resolver      string   `json:"resolver"`
	Domain        string   `json:"domain"`
	QType         string   `json:"qtype"`
	Protocol      string   `json:"protocol"`
	Answers       []string `json:"answers"`
	LatencyMS     int64    `json:"latency_ms"`
	RCode         int      `json:"rcode"`
	Recursive     bool     `json:"recursive"`
	Authoritative bool     `json:"authoritative"`
	DNSSEC        bool     `json:"dnssec"`
	EDNS          bool     `json:"edns"`
	Vendor        string   `json:"vendor"`
	Health        int      `json:"health"`
	Error         string   `json:"error,omitempty"`
}

type dnsJob struct {
	resolver string
	domain   string
	qtype    string
}

func scanDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req dnsScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	metricDNSRuns.Add(1)
	req.normalize()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	total := len(req.Resolvers) * len(req.Domains) * len(req.QTypes) * req.Samples
	if err := enc.Encode(map[string]any{"type": "init", "total": total}); err != nil {
		cancel()
		return
	}
	flush(flusher)

	jobs := make(chan dnsJob)
	results := make(chan dnsResult, req.Workers)
	var done atomic.Int64
	var wg sync.WaitGroup
	limiter := newRateLimiter(req.RatePerSecond)
	for i := 0; i < req.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				waitRate(ctx, limiter, req.JitterMS)
				res := runDNSQuery(ctx, job, req.TimeoutMS)
				select {
				case <-ctx.Done():
					return
				case results <- res:
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for sample := 0; sample < req.Samples; sample++ {
			for _, resolver := range req.Resolvers {
				for _, domain := range req.Domains {
					for _, qtype := range req.QTypes {
						select {
						case <-ctx.Done():
							return
						case jobs <- dnsJob{resolver: resolver, domain: domain, qtype: qtype}:
						}
					}
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	for res := range results {
		checked := done.Add(1)
		if err := enc.Encode(map[string]any{"type": "dns", "result": res, "checked": checked, "total": total}); err != nil {
			cancel()
			return
		}
		flush(flusher)
	}
	if err := enc.Encode(map[string]any{"type": "done", "stopped": ctx.Err() != nil}); err != nil {
		cancel()
		return
	}
	flush(flusher)
}

func (r *dnsScanRequest) normalize() {
	r.Resolvers = unique(r.Resolvers)
	if len(r.Resolvers) == 0 {
		r.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}
	}
	for i, resolver := range r.Resolvers {
		if !strings.Contains(resolver, ":") {
			r.Resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}
	r.Domains = unique(r.Domains)
	if len(r.Domains) == 0 {
		r.Domains = []string{"cloudflare.com", "google.com", randomNXDomain()}
	}
	if len(r.QTypes) == 0 {
		r.QTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "SOA"}
	}
	var qtypes []string
	for _, qt := range r.QTypes {
		qt = strings.ToUpper(strings.TrimSpace(qt))
		if dnsTypeCode(qt) != 0 {
			qtypes = append(qtypes, qt)
		}
	}
	r.QTypes = unique(qtypes)
	if r.TimeoutMS < 200 || r.TimeoutMS > 10000 {
		r.TimeoutMS = 1500
	}
	if r.Workers <= 0 || r.Workers > 512 {
		r.Workers = max(4, runtime.NumCPU()*2)
	}
	if r.Samples <= 0 || r.Samples > 20 {
		r.Samples = 1
	}
	if r.RatePerSecond < 0 {
		r.RatePerSecond = 0
	}
	if r.JitterMS < 0 {
		r.JitterMS = 0
	}
}

func runDNSQuery(ctx context.Context, job dnsJob, timeoutMS int) dnsResult {
	res := dnsResult{Resolver: job.resolver, Domain: job.domain, QType: job.qtype, Protocol: "udp", Vendor: dnsVendor(job.resolver)}
	qtype := dns.StringToType[strings.ToUpper(job.qtype)]
	if qtype == 0 {
		res.Error = "unsupported query type"
		return res
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(job.domain), qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)
	client := &dns.Client{
		Net:     "udp",
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
		Dialer: &net.Dialer{
			LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 0},
			Timeout:   time.Duration(timeoutMS) * time.Millisecond,
		},
	}
	in, rtt, err := client.ExchangeContext(ctx, msg, job.resolver)
	if ctx.Err() != nil {
		res.Error = ctx.Err().Error()
		res.Health = scoreDNS(res)
		return res
	}
	res.LatencyMS = rtt.Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.Health = scoreDNS(res)
		return res
	}
	parsed := parseDNSMessage(in)
	res.Answers = parsed.answers
	res.RCode = parsed.rcode
	res.Recursive = parsed.ra
	res.Authoritative = parsed.aa
	res.DNSSEC = parsed.ad
	res.EDNS = parsed.edns
	res.Health = scoreDNS(res)
	return res
}

type parsedDNS struct {
	answers []string
	rcode   int
	ra      bool
	aa      bool
	ad      bool
	edns    bool
}

func parseDNSMessage(msg *dns.Msg) parsedDNS {
	var out parsedDNS
	if msg == nil {
		return out
	}
	out.rcode = msg.Rcode
	out.ra = msg.RecursionAvailable
	out.aa = msg.Authoritative
	out.ad = msg.AuthenticatedData
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out.answers = append(out.answers, v.A.String())
		case *dns.AAAA:
			out.answers = append(out.answers, v.AAAA.String())
		case *dns.CNAME:
			out.answers = append(out.answers, strings.TrimSuffix(v.Target, "."))
		case *dns.NS:
			out.answers = append(out.answers, strings.TrimSuffix(v.Ns, "."))
		case *dns.MX:
			out.answers = append(out.answers, fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")))
		case *dns.TXT:
			out.answers = append(out.answers, strings.Join(v.Txt, " "))
		case *dns.SOA:
			out.answers = append(out.answers, fmt.Sprintf("%s %s serial=%d", strings.TrimSuffix(v.Ns, "."), strings.TrimSuffix(v.Mbox, "."), v.Serial))
		default:
			out.answers = append(out.answers, rr.String())
		}
	}
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			out.edns = true
			break
		}
	}
	return out
}

func dnsTypeCode(qtype string) uint16 {
	if code, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(qtype))]; ok {
		return code
	}
	return 0
}

func scoreDNS(r dnsResult) int {
	score := 0
	if r.Error == "" {
		score += 40
	}
	if r.Recursive {
		score += 15
	}
	if r.EDNS {
		score += 15
	}
	if r.DNSSEC {
		score += 10
	}
	if len(r.Answers) > 0 || r.RCode == 3 {
		score += 10
	}
	if r.LatencyMS > 0 {
		score += max(0, 30-int(r.LatencyMS/20))
	}
	return score
}

func dnsVendor(resolver string) string {
	host, _, _ := net.SplitHostPort(resolver)
	switch host {
	case "1.1.1.1", "1.0.0.1":
		return "Cloudflare"
	case "8.8.8.8", "8.8.4.4":
		return "Google"
	case "9.9.9.9", "149.112.112.112":
		return "Quad9"
	case "208.67.222.222", "208.67.220.220":
		return "OpenDNS"
	default:
		return "Unknown"
	}
}

func randomNXDomain() string {
	return "nx-" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".invalid"
}
