package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
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
	Resolver       string         `json:"resolver"`
	Domain         string         `json:"domain"`
	QType          string         `json:"qtype"`
	Protocol       string         `json:"protocol"`
	Answers        []string       `json:"answers"`
	CNAMEChain     []string       `json:"cname_chain,omitempty"`
	CNAMELoop      bool           `json:"cname_loop,omitempty"`
	TTLMin         *uint32        `json:"ttl_min,omitempty"`
	TTLRecords     []dnsTTLRecord `json:"ttl_records,omitempty"`
	LatencyMS      int64          `json:"latency_ms"`
	RCode          int            `json:"rcode"`
	Recursive      bool           `json:"recursive"`
	Authoritative  bool           `json:"authoritative"`
	DNSSEC         bool           `json:"dnssec"`
	EDNS           bool           `json:"edns"`
	Truncated      bool           `json:"truncated"`
	RetriedOverTCP bool           `json:"retried_over_tcp"`
	Attempts       []dnsAttempt   `json:"attempts,omitempty"`
	RawSize        int            `json:"raw_size,omitempty"`
	Vendor         string         `json:"vendor"`
	Health         int            `json:"health"`
	ErrorCode      string         `json:"error_code,omitempty"`
	Error          string         `json:"error,omitempty"`
}

type dnsTTLRecord struct {
	Name  string `json:"name"`
	RType string `json:"rtype"`
	TTL   uint32 `json:"ttl"`
}

type dnsAttempt struct {
	Transport string `json:"transport"`
	Outcome   string `json:"outcome"`
	Truncated bool   `json:"truncated"`
	LatencyMS *int64 `json:"latency_ms,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

type dnsJob struct {
	resolver string
	domain   string
	qtype    string
}

const (
	maxCNAMEChainDepth = 16
)

func scanDNS(w http.ResponseWriter, r *http.Request) {
	var serial uint64
	if r.Method != http.MethodPost {
		writePublicMethodNotAllowed(w, http.MethodPost)
		return
	}
	if activeControlPlane != nil {
		activeControlPlane.setState("dns_running")
		defer activeControlPlane.setState("idle")
	}
	var req dnsScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writePublicBadRequest(w, "invalid dns scan request body")
		return
	}
	metricDNSRuns.Add(1)
	req.normalize()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeSerial++
	serial = activeSerial
	activeCancel = cancel
	activeCancelMu.Unlock()
	defer func() {
		activeCancelMu.Lock()
		if activeSerial == serial {
			activeCancel = nil
		}
		activeCancelMu.Unlock()
	}()

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
	if r.TimeoutMS <= 0 {
		r.TimeoutMS = 1500
	}
	if r.Workers <= 0 {
		r.Workers = max(4, runtime.NumCPU()*2)
	}
	if r.Samples <= 0 {
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
		res.ErrorCode = "DNS_FAILED"
		return res
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(job.domain), qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)
	in, rtt, err := exchangeDNS(ctx, msg, job.resolver, "udp", timeoutMS)
	res.Attempts = append(res.Attempts, dnsAttemptFromExchange("udp", in, rtt, err))
	if ctx.Err() != nil {
		res.Error = ctx.Err().Error()
		res.ErrorCode = classifyDNSError(ctx.Err())
		res.Health = scoreDNS(res)
		return res
	}
	res.LatencyMS = rtt.Milliseconds()
	if err != nil {
		res.Error = err.Error()
		res.ErrorCode = classifyDNSError(err)
		res.Health = scoreDNS(res)
		return res
	}
	if in != nil && in.Truncated {
		res.Truncated = true
		res.RetriedOverTCP = true
		tcpIn, tcpRTT, tcpErr := exchangeDNS(ctx, msg, job.resolver, "tcp", timeoutMS)
		res.Attempts = append(res.Attempts, dnsAttemptFromExchange("tcp", tcpIn, tcpRTT, tcpErr))
		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
			res.ErrorCode = classifyDNSError(ctx.Err())
			res.Health = scoreDNS(res)
			return res
		}
		if tcpErr == nil && tcpIn != nil {
			in = tcpIn
			res.Protocol = "tcp"
			res.LatencyMS += tcpRTT.Milliseconds()
			res.Error = ""
			res.ErrorCode = ""
		} else if tcpErr != nil {
			res.Error = tcpErr.Error()
			res.ErrorCode = "DNS_TRUNCATED_RETRY_FAILED"
		}
	}
	parsed := parseDNSMessage(in)
	res.Answers = parsed.answers
	res.CNAMEChain = parsed.cnameChain
	res.CNAMELoop = parsed.cnameLoop
	res.TTLMin = parsed.ttlMin
	res.TTLRecords = parsed.ttlRecords
	res.RCode = parsed.rcode
	res.Recursive = parsed.ra
	res.Authoritative = parsed.aa
	res.DNSSEC = parsed.ad
	res.EDNS = parsed.edns
	res.RawSize = parsed.rawSize
	res.Truncated = res.Truncated || parsed.truncated
	if res.ErrorCode == "" {
		res.ErrorCode = dnsRCodeErrorCode(res.RCode, len(res.Answers))
	}
	if parsed.cnameLoop {
		res.ErrorCode = "DNS_CNAME_LOOP"
	}
	res.Health = scoreDNS(res)
	return res
}

type parsedDNS struct {
	answers    []string
	cnameChain []string
	cnameLoop  bool
	ttlMin     *uint32
	ttlRecords []dnsTTLRecord
	rcode      int
	ra         bool
	aa         bool
	ad         bool
	edns       bool
	truncated  bool
	rawSize    int
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
	out.truncated = msg.Truncated
	out.rawSize = msg.Len()
	cnames := make(map[string]string)
	for _, rr := range msg.Answer {
		recordTTL(&out, rr.Header())
		switch v := rr.(type) {
		case *dns.A:
			out.answers = append(out.answers, v.A.String())
		case *dns.AAAA:
			out.answers = append(out.answers, v.AAAA.String())
		case *dns.CNAME:
			target := strings.TrimSuffix(v.Target, ".")
			out.answers = append(out.answers, target)
			cnames[strings.TrimSuffix(v.Hdr.Name, ".")] = target
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
	out.cnameChain, out.cnameLoop = collectCNAMEChain(cnames)
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			out.edns = true
			break
		}
	}
	return out
}

func collectCNAMEChain(cnames map[string]string) ([]string, bool) {
	if len(cnames) == 0 {
		return nil, false
	}
	keys := make([]string, 0, len(cnames))
	for key := range cnames {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var chain []string
	loop := false
	for _, start := range keys {
		seen := map[string]bool{start: true}
		current := start
		for depth := 0; depth < maxCNAMEChainDepth; depth++ {
			next, ok := cnames[current]
			if !ok {
				break
			}
			if !stringInSlice(chain, next) {
				chain = append(chain, next)
			}
			if seen[next] {
				loop = true
				break
			}
			seen[next] = true
			current = next
		}
		if _, ok := cnames[current]; ok && len(seen) >= maxCNAMEChainDepth {
			loop = true
		}
	}
	return chain, loop
}

func stringInSlice(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func exchangeDNS(ctx context.Context, msg *dns.Msg, resolver, network string, timeoutMS int) (*dns.Msg, time.Duration, error) {
	client := &dns.Client{
		Net:     network,
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
		Dialer:  &net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond},
	}
	return client.ExchangeContext(ctx, msg, resolver)
}

func dnsAttemptFromExchange(network string, msg *dns.Msg, rtt time.Duration, err error) dnsAttempt {
	var latency *int64
	if rtt > 0 {
		ms := rtt.Milliseconds()
		latency = &ms
	}
	attempt := dnsAttempt{
		Transport: network,
		Outcome:   "success",
		LatencyMS: latency,
	}
	if msg != nil && msg.Truncated {
		attempt.Truncated = true
		attempt.Outcome = "truncated"
	}
	if err != nil {
		attempt.Outcome = "failed"
		attempt.ErrorCode = classifyDNSError(err)
		if attempt.ErrorCode == "DNS_TIMEOUT" {
			attempt.Outcome = "timeout"
		}
		attempt.Error = err.Error()
	}
	return attempt
}

func dnsRCodeErrorCode(rcode int, answerCount int) string {
	switch rcode {
	case dns.RcodeSuccess:
		if answerCount == 0 {
			return "DNS_NO_ANSWER"
		}
		return ""
	case dns.RcodeNameError:
		return "DNS_NXDOMAIN"
	case dns.RcodeServerFailure:
		return "DNS_SERVFAIL"
	case dns.RcodeRefused:
		return "DNS_REFUSED"
	case dns.RcodeFormatError:
		return "DNS_MALFORMED_RESPONSE"
	default:
		return "DNS_FAILED"
	}
}

func classifyDNSError(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	lower := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout(), strings.Contains(lower, "timeout"):
		return "DNS_TIMEOUT"
	case strings.Contains(lower, "refused"):
		return "DNS_RESOLVER_UNREACHABLE"
	case strings.Contains(lower, "malformed"):
		return "DNS_MALFORMED_RESPONSE"
	default:
		return "DNS_FAILED"
	}
}

func recordTTL(out *parsedDNS, hdr *dns.RR_Header) {
	if out == nil || hdr == nil {
		return
	}
	ttl := hdr.Ttl
	name := strings.TrimSuffix(hdr.Name, ".")
	out.ttlRecords = append(out.ttlRecords, dnsTTLRecord{Name: name, RType: dns.TypeToString[hdr.Rrtype], TTL: ttl})
	if out.ttlMin == nil || ttl < *out.ttlMin {
		copyTTL := ttl
		out.ttlMin = &copyTTL
	}
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
