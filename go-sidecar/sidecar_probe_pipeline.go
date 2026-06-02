package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

func probe(ctx context.Context, target string, port int, req scanRequest, batchNo int, routePlan scanRoutePlan, opts probeOptions) result {
	res := result{Target: target, Port: port, BatchNumber: batchNo, NetworkClassification: "unknown", PlanID: opts.PlanID, ResultCorrelationID: opts.ResultCorrelationID, TargetPlan: opts.TargetPlan}
	routePlan.ApplyRequestedToResult(&res)
	var phases []PhaseResult
	dnsStart := time.Now()
	var ips []string
	var sni string
	var err error
	if strings.TrimSpace(opts.FixedIP) != "" {
		ips = []string{strings.TrimSpace(opts.FixedIP)}
		sni = strings.TrimSpace(opts.FixedSNI)
		if opts.SNIMode == "ip_only_no_sni" {
			sni = ""
		}
	} else {
		ips, sni, err = resolveTargetCandidates(target)
	}
	if len(ips) > 0 {
		res.IP = ips[0]
	}
	res.SNI = sni
	if err != nil {
		dnsPhase := newPhaseFailure("dns", err, time.Since(dnsStart).Milliseconds(), "DNS_RESOLUTION_FAILED")
		res.PhaseResults = []PhaseResult{dnsPhase}
		res.FinalPhase = "dns"
		res.ErrorCode = dnsPhase.ErrorCode
		res.Error = err.Error()
		return res
	}
	snis := candidateSNIs(sni, req.SNIs, req.MultiSNI)
	var lastErr error
	var lastErrCode string
	var observedRoute *RouteObservation

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		res.IP = ip
		res.applyProviderObservation(observeProvider(ip))
		res.NetworkClassification = detectNetworkClassification(ip, sni, "")
		var tlsAttempted bool
		var anyTCPOK bool
		for _, candidateSNI := range snis {
			if ctx.Err() != nil {
				break
			}
			fingerprint := chooseTLSFingerprint(req.TLSFingerprint)
			tlsAttempted = true
			start := time.Now()
			conn, tcpOK, tlsInfo, tlsOK, tlsErr, routeObs := tlsProbeOpen(ctx, ip, port, candidateSNI, req.TimeoutMS, fingerprint, DPIObfuscationOptions{EnablePayloadSplitting: req.EnablePayloadSplitting, SplitByteBoundary: req.SplitByteBoundary}, routePlan)
			if tcpOK {
				anyTCPOK = true
			}
			if routeObs != nil {
				observedRoute = routeObs
			}
			if tlsErr != nil {
				lastErr = tlsErr
				lastErrCode = classifyNetworkError(tlsErr, "tls")
				phases = append(phases, newPhaseFailure("tls", tlsErr, time.Since(start).Milliseconds(), lastErrCode))
			}
			if tlsOK {
				elapsed := time.Since(start).Milliseconds()
				res.TCP = true
				res.LatencyMS = elapsed
				res.TLS = true
				res.SNI = candidateSNI
				res.TLSVersion = tlsInfo.Version
				res.TLSCipher = tlsInfo.Cipher
				res.CertVerified = tlsInfo.Verified
				res.ALPN = tlsInfo.ALPN
				res.TLSFingerprint = fingerprint
				res.CertSubject = tlsInfo.Subject
				res.NetworkClassification = detectNetworkClassification(ip, candidateSNI, tlsInfo.Subject)
				phases = appendTLSOutcomePhases(phases, candidateSNI, tlsInfo.Verified, elapsed)
				if req.HTTPProbe {
					httpStart := time.Now()
					res.HTTP, res.HTTPStatus, res.ServerHeader, res.CacheHeader, res.AltSvc, res.HTTP3Hint, res.HTTPProbeCode = probeHTTPOverNegotiatedALPN(ctx, conn, ip, candidateSNI, req.HTTPPath, req.TimeoutMS, tlsInfo.ALPN)
					httpPhase := httpPhaseFromALPN(tlsInfo.ALPN)
					httpMs := time.Since(httpStart).Milliseconds()
					if res.HTTP {
						phases = append(phases, newPhaseSuccess(httpPhase, httpMs))
					} else if strings.TrimSpace(res.HTTPProbeCode) != "" {
						phases = append(phases, newPhaseFailure(httpPhase, fmt.Errorf("%s", res.HTTPProbeCode), httpMs, res.HTTPProbeCode))
					}
				}
				_ = conn.Close()
				break
			}
		}
		if anyTCPOK {
			res.TCP = true
		}
		if !res.TLS && tlsAttempted && !anyTCPOK {
			tcpStart := time.Now()
			res.TCP, err = tcpWithError(ctx, ip, port, req.TimeoutMS, routePlan, &observedRoute)
			tcpMs := time.Since(tcpStart).Milliseconds()
			res.LatencyMS = tcpMs
			if err != nil {
				lastErr = err
				lastErrCode = classifyNetworkError(err, "tcp")
				phases = append(phases, newPhaseFailure("tcp", err, tcpMs, lastErrCode))
			} else {
				phases = append(phases, newPhaseSuccess("tcp", tcpMs))
			}
		}
		if res.TLS || res.TCP {
			break
		}
	}
	if !res.TLS && !res.TCP && lastErr != nil {
		res.ErrorCode = lastErrCode
		res.Error = lastErr.Error()
	}
	if routePlan.Valid {
		if observedRoute != nil {
			routePlan.ApplyObservedToResult(&res, observedRoute)
		} else {
			routePlan.ApplyRouteNotObserved(&res)
		}
		if routePhase, ok := buildRoutePhaseResult(res); ok {
			phases = append(phases, routePhase)
		}
	}
	res.PhaseResults = phases
	res.FinalPhase = finalizeFinalPhase(res, phases, lastErrCode)
	if routePlan.Valid && strings.TrimSpace(res.RouteErrorCode) != "" && res.FinalPhase == "" {
		res.FinalPhase = "route"
	}
	res.Score = score(res)
	return res
}

func resolveTarget(target string) (string, string, error) {
	ips, sni, err := resolveTargetCandidates(target)
	if err != nil {
		return "", sni, err
	}
	return ips[0], sni, nil
}

func resolveTargetCandidates(target string) ([]string, string, error) {
	if net.ParseIP(target) != nil {
		return []string{target}, "", nil
	}
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return nil, "", errors.New("DNS failed")
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil && ip.To16() != nil {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, "", errors.New("no IP address")
	}
	return uniqueInOrder(out), target, nil
}

func candidateSNIs(resolvedSNI string, corpus []string, multiSNI bool) []string {
	if multiSNI {
		candidates := make([]string, 0, len(corpus)+1)
		if strings.TrimSpace(resolvedSNI) != "" {
			candidates = append(candidates, resolvedSNI)
		}
		candidates = append(candidates, corpus...)
		return uniqueInOrder(candidates)
	}
	if strings.TrimSpace(resolvedSNI) != "" {
		return []string{resolvedSNI}
	}
	if len(corpus) > 0 {
		return []string{corpus[0]}
	}
	return []string{""}
}

func uniqueInOrder(xs []string) []string {
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
	return out
}

func tcp(ctx context.Context, ip string, port int, timeoutMS int) bool {
	ok, _ := tcpWithError(ctx, ip, port, timeoutMS, scanRoutePlan{}, nil)
	return ok
}

func tcpWithError(ctx context.Context, ip string, port int, timeoutMS int, routePlan scanRoutePlan, observedRoute **RouteObservation) (bool, error) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	if routePlan.HasRuntimeRoute() {
		cfg := routePlan.RouteConfigForProbe(timeoutMS)
		conn, obs, err := dialViaRoute(ctx, network, target, cfg)
		if observedRoute != nil {
			*observedRoute = &obs
		}
		if err != nil {
			return false, err
		}
		_ = conn.Close()
		return true, nil
	}
	d := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
	conn, err := d.DialContext(ctx, network, target)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}

type tlsInfo struct {
	Version  string
	Cipher   string
	ALPN     string
	Verified bool
	Subject  string
}

func tlsProbe(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions) (tlsInfo, bool) {
	conn, _, info, ok, _, _ := tlsProbeOpen(ctx, ip, port, sni, timeoutMS, fingerprint, opts, scanRoutePlan{})
	if conn != nil {
		_ = conn.Close()
	}
	return info, ok
}

func tlsProbeOpen(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, tlsInfo, bool, error, *RouteObservation) {
	conn, tcpOK, err, routeObs := dialUTLS(ctx, ip, port, sni, timeoutMS, fingerprint, opts, routePlan)
	if err != nil {
		return nil, tcpOK, tlsInfo{}, false, err, routeObs
	}
	state := conn.ConnectionState()
	info := tlsInfo{Version: tlsVersionName(state.Version), Cipher: cipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol}
	if len(state.PeerCertificates) > 0 {
		verifyName := strings.TrimSpace(sni)
		if verifyName == "" {
			verifyName = conn.RemoteAddr().String()
			if host, _, err := net.SplitHostPort(verifyName); err == nil {
				verifyName = host
			}
		}
		optsVerify := x509.VerifyOptions{
			DNSName:       verifyName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			optsVerify.Intermediates.AddCert(cert)
		}
		_, verifyErr := state.PeerCertificates[0].Verify(optsVerify)
		info.Verified = verifyErr == nil
		info.Subject = state.PeerCertificates[0].Subject.String()
	}
	if ctx.Err() != nil {
		_ = conn.Close()
		return nil, true, info, false, ctx.Err(), routeObs
	}
	return conn, true, info, true, nil, routeObs
}

func httpProbe(ctx context.Context, ip string, port int, sni, path string, timeoutMS int, fingerprint string) (bool, int, string, string, string, bool) {
	conn, _, err, _ := dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"http/1.1"}, DPIObfuscationOptions{}, scanRoutePlan{})
	if err != nil {
		return false, 0, "", "", "", false
	}
	defer conn.Close()
	httpOK, status, server, cache, altSvc, http3, _ := httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
	return httpOK, status, server, cache, altSvc, http3
}

func httpProbeConn(ctx context.Context, conn net.Conn, ip string, sni, path string, timeoutMS int) (bool, int, string, string, string, bool, string) {
	rollingDeadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = conn.SetDeadline(rollingDeadline)

	host := strings.TrimSpace(sni)
	if host == "" {
		host = ip
	}
	if _, err := fmt.Fprintf(conn, "HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: MaybeScanner/1.2\r\nCache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\nX-Maybe-Cachebuster: %d\r\nConnection: close\r\n\r\n", path, host, time.Now().UnixNano()); err != nil {
		return false, 0, "", "", "", false, classifyNetworkError(err, "http")
	}
	reader := pooledReader(io.LimitReader(conn, 64*1024))
	defer putReader(reader)

	_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
	line, err := readLimitedLine(reader, 4096)
	status := parseHTTPStatus(line)
	if err != nil && errors.Is(err, io.EOF) && status > 0 {
		// Accept short-lived but syntactically valid status-line responses that close immediately.
		err = nil
	}
	if status == 0 {
		if err != nil {
			return false, 0, "", "", "", false, classifyNetworkError(err, "http")
		}
		return false, 0, "", "", "", false, "HTTP_PARSE_FAILED"
	}
	server, cache, altSvc := "", "", ""
	if err == nil {
		for i := 0; i < 48; i++ {
			_ = conn.SetReadDeadline(time.Now().Add(750 * time.Millisecond))
			header, hErr := readLimitedLine(reader, 4096)
			if hErr != nil {
				if errors.Is(hErr, io.EOF) && strings.TrimSpace(header) == "" {
					break
				}
				return false, status, server, cache, altSvc, false, classifyNetworkError(hErr, "http")
			}
			header = strings.TrimRight(header, "\r\n")
			if strings.TrimSpace(header) == "" {
				break
			}
			lower := strings.ToLower(header)
			if strings.HasPrefix(lower, "server:") {
				server = strings.TrimSpace(header[len("server:"):])
			}
			if strings.HasPrefix(lower, "x-cache:") || strings.HasPrefix(lower, "cf-cache-status:") || strings.HasPrefix(lower, "age:") {
				if cache != "" {
					cache += "; "
				}
				cache += strings.TrimSpace(header)
			}
			if strings.HasPrefix(lower, "alt-svc:") {
				altSvc = strings.TrimSpace(header[len("alt-svc:"):])
			}
		}
	}
	return ctx.Err() == nil && status < 500, status, server, cache, altSvc, strings.Contains(strings.ToLower(altSvc), "h3"), ""
}

func probeHTTPOverNegotiatedALPN(ctx context.Context, conn net.Conn, ip string, sni string, path string, timeoutMS int, negotiatedALPN string) (bool, int, string, string, string, bool, string) {
	if strings.EqualFold(strings.TrimSpace(negotiatedALPN), "h2") {
		return false, 0, "", "", "", false, "HTTP2_UNSUPPORTED_IN_PROBE"
	}
	httpOK, status, server, cache, altSvc, http3, probeCode := httpProbeConn(ctx, conn, ip, sni, path, timeoutMS)
	return httpOK, status, server, cache, altSvc, http3, probeCode
}

func dialUTLS(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, error, *RouteObservation) {
	return dialUTLSWithALPN(ctx, ip, port, sni, timeoutMS, fingerprint, []string{"h2", "http/1.1"}, opts, routePlan)
}

func dialUTLSWithALPN(ctx context.Context, ip string, port int, sni string, timeoutMS int, fingerprint string, nextProtos []string, opts DPIObfuscationOptions, routePlan scanRoutePlan) (*tls.UConn, bool, error, *RouteObservation) {
	network := "tcp4"
	if strings.Contains(ip, ":") {
		network = "tcp6"
	}
	target := net.JoinHostPort(ip, strconv.Itoa(port))
	var rawConn net.Conn
	var routeObs *RouteObservation
	if routePlan.HasRuntimeRoute() {
		cfg := routePlan.RouteConfigForProbe(timeoutMS)
		conn, obs, err := dialViaRoute(ctx, network, target, cfg)
		routeObs = &obs
		if err != nil {
			return nil, false, err, routeObs
		}
		rawConn = conn
	} else {
		conn, err := DialObfuscatedSocket(ctx, network, target, time.Duration(timeoutMS)*time.Millisecond, opts)
		if err != nil {
			return nil, false, err, nil
		}
		rawConn = conn
	}
	deadline := time.Now().Add(time.Duration(timeoutMS) * time.Millisecond)
	_ = rawConn.SetDeadline(deadline)
	serverName := strings.TrimSpace(sni)
	conn := tls.UClient(rawConn, &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS12, NextProtos: nextProtos,
		// This is a scanner: continue handshakes so mismatched SNI/Host routes and
		// edge certificates can be measured and reported instead of hidden as TLS failures.
		InsecureSkipVerify: true,
	}, clientHelloID(fingerprint))
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = rawConn.Close()
		case <-done:
		}
	}()
	if err := conn.Handshake(); err != nil {
		close(done)
		_ = rawConn.Close()
		return nil, true, err, routeObs
	}
	close(done)
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, true, err, routeObs
	}
	_ = conn.SetDeadline(deadline)
	return conn, true, nil, routeObs
}
