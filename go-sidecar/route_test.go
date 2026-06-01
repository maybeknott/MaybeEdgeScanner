package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateRouteConfigRejectsCRLF(t *testing.T) {
	cfg := RouteConfig{
		RouteID:      "bad\r\nroute",
		Type:         RouteHTTPConnect,
		ProxyAddress: "127.0.0.1:8080",
		Timeout:      time.Second,
	}
	if err := validateRouteConfig(cfg); err == nil {
		t.Fatal("expected CR/LF validation failure")
	}
}

func TestValidateRouteConfigRejectsProviderMetadataCRLF(t *testing.T) {
	cfg := RouteConfig{
		RouteID:      "route-windscribe",
		Type:         RouteSOCKS5,
		ProxyAddress: "127.0.0.1:1080",
		Timeout:      time.Second,
		DNSPolicy:    "remote",
		ProviderID:   "windscribe",
		ProtocolMode: "wireguard\r\nx",
	}
	if err := validateRouteConfig(cfg); err == nil {
		t.Fatal("expected provider metadata CR/LF validation failure")
	}
}

func TestDialViaRouteDirect(t *testing.T) {
	listener := listenLocalTCP(t)
	defer listener.Close()
	go acceptAndClose(t, listener)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", listener.Addr().String(), RouteConfig{
		RouteID:   "direct-test",
		Type:      RouteDirect,
		Timeout:   time.Second,
		DNSPolicy: "not_applicable",
	})
	if err != nil {
		t.Fatalf("direct dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.RouteType != RouteDirect {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteCarriesEdgeRouteMetadata(t *testing.T) {
	listener := listenLocalTCP(t)
	defer listener.Close()
	go acceptAndClose(t, listener)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", listener.Addr().String(), RouteConfig{
		RouteID:          "route-windscribe-profile",
		Type:             RouteDirect,
		Timeout:          time.Second,
		DNSPolicy:        "route_dns",
		ProviderID:       "windscribe",
		RouteBinding:     "external_vpn_observation",
		ProtocolMode:     "wireguard",
		AuthMode:         "wsnet_session_ref",
		SplitTunnel:      "scanner_app_only",
		UpstreamMode:     "none",
		DownstreamMode:   "vpn_interface",
		ProxyGatewayMode: "loopback_only",
	})
	if err != nil {
		t.Fatalf("direct dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.ProviderID != "windscribe" ||
		obs.RouteBinding != "external_vpn_observation" ||
		obs.ProtocolMode != "wireguard" ||
		obs.AuthMode != "wsnet_session_ref" ||
		obs.DownstreamMode != "vpn_interface" {
		t.Fatalf("edge route metadata not carried into observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectSuccess(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnect(t, proxyListener, http.StatusOK)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("192.0.2.10", "443"), RouteConfig{
		RouteID:      "connect-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err != nil {
		t.Fatalf("CONNECT dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.ProxyStatus != http.StatusOK {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectAuthRequired(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnect(t, proxyListener, http.StatusProxyAuthRequired)

	_, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("192.0.2.10", "443"), RouteConfig{
		RouteID:      "connect-auth-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err == nil {
		t.Fatal("expected CONNECT auth failure")
	}
	if obs.ErrorCode != "PROXY_407_AUTH_REQUIRED" || obs.ProxyStatus != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectMalformedResponse(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnectMalformed(t, proxyListener)

	_, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("192.0.2.10", "443"), RouteConfig{
		RouteID:      "connect-malformed-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err == nil {
		t.Fatal("expected CONNECT malformed response failure")
	}
	if obs.ErrorCode != "PROXY_CONNECT_MALFORMED_RESPONSE" {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectTimeout(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneHTTPConnectNoResponse(t, proxyListener, 200*time.Millisecond)

	_, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("192.0.2.10", "443"), RouteConfig{
		RouteID:      "connect-timeout-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      50 * time.Millisecond,
		DNSPolicy:    "remote",
	})
	if err == nil {
		t.Fatal("expected CONNECT timeout failure")
	}
	if obs.ErrorCode != "PROXY_TIMEOUT" {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectFormatsIPv6TargetWithBrackets(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	target := net.JoinHostPort("2001:db8::1", "443")
	go serveOneHTTPConnectExpectTarget(t, proxyListener, http.StatusOK, target)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", target, RouteConfig{
		RouteID:      "connect-ipv6-target-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err != nil {
		t.Fatalf("CONNECT IPv6 target dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.ProxyStatus != http.StatusOK {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteHTTPConnectPreservesHostnameTargetForRemoteDNS(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	target := net.JoinHostPort("example.com", "443")
	go serveOneHTTPConnectExpectTarget(t, proxyListener, http.StatusOK, target)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", target, RouteConfig{
		RouteID:      "connect-hostname-target-test",
		Type:         RouteHTTPConnect,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err != nil {
		t.Fatalf("CONNECT hostname target dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.ProxyStatus != http.StatusOK {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.DNSPolicy != "remote" {
		t.Fatalf("expected remote DNS policy in observation, got %+v", obs)
	}
}

func TestDialViaRouteSOCKS5Success(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneSOCKS5(t, proxyListener)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("198.51.100.9", "443"), RouteConfig{
		RouteID:      "socks5-test",
		Type:         RouteSOCKS5,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err != nil {
		t.Fatalf("SOCKS5 dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.RouteType != RouteSOCKS5 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteSOCKS5RejectsNoAcceptableMethods(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneSOCKS5RejectMethod(t, proxyListener)

	_, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("198.51.100.9", "443"), RouteConfig{
		RouteID:      "socks5-reject-method-test",
		Type:         RouteSOCKS5,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err == nil {
		t.Fatal("expected SOCKS5 reject-method failure")
	}
	if obs.ErrorCode != "PROXY_CONNECT_REJECTED" {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteSOCKS5RejectsReplyCodeFailure(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	go serveOneSOCKS5ReplyFailure(t, proxyListener, 0x05)

	_, obs, err := dialViaRoute(context.Background(), "tcp", net.JoinHostPort("198.51.100.9", "443"), RouteConfig{
		RouteID:      "socks5-reply-failure-test",
		Type:         RouteSOCKS5,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err == nil {
		t.Fatal("expected SOCKS5 reply-code failure")
	}
	if obs.ErrorCode != "PROXY_CONNECT_REJECTED" {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestDialViaRouteSOCKS5PreservesHostnameTargetForRemoteDNS(t *testing.T) {
	proxyListener := listenLocalTCP(t)
	defer proxyListener.Close()
	target := net.JoinHostPort("example.com", "443")
	go serveOneSOCKS5ExpectDomainTarget(t, proxyListener, "example.com", 443)

	conn, obs, err := dialViaRoute(context.Background(), "tcp", target, RouteConfig{
		RouteID:      "socks5-hostname-target-test",
		Type:         RouteSOCKS5,
		ProxyAddress: proxyListener.Addr().String(),
		Timeout:      time.Second,
		DNSPolicy:    "remote",
	})
	if err != nil {
		t.Fatalf("SOCKS5 hostname target dial failed: %v", err)
	}
	_ = conn.Close()
	if obs.Status != "success" || obs.RouteType != RouteSOCKS5 {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if obs.DNSPolicy != "remote" {
		t.Fatalf("expected remote DNS policy in observation, got %+v", obs)
	}
}

func listenLocalTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	return listener
}

func acceptAndClose(t *testing.T, listener net.Listener) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	_ = conn.Close()
}

func serveOneHTTPConnect(t *testing.T, listener net.Listener, status int) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	line, ok := readHTTPConnectRequestLine(t, conn)
	if !ok {
		return
	}
	if !strings.HasPrefix(line, "CONNECT ") {
		t.Errorf("expected CONNECT request, got %q", line)
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

func serveOneHTTPConnectExpectTarget(t *testing.T, listener net.Listener, status int, wantTarget string) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	line, ok := readHTTPConnectRequestLine(t, conn)
	if !ok {
		return
	}
	expectedLinePrefix := "CONNECT " + wantTarget + " HTTP/1.1"
	if !strings.HasPrefix(strings.TrimRight(line, "\r\n"), expectedLinePrefix) {
		t.Errorf("expected CONNECT request line prefix %q, got %q", expectedLinePrefix, strings.TrimRight(line, "\r\n"))
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

func serveOneHTTPConnectMalformed(t *testing.T, listener net.Listener) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, ok := readHTTPConnectRequestLine(t, conn); !ok {
		return
	}
	_, _ = io.WriteString(conn, "not-http\r\n")
}

func serveOneHTTPConnectNoResponse(t *testing.T, listener net.Listener, sleep time.Duration) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, ok := readHTTPConnectRequestLine(t, conn); !ok {
		return
	}
	time.Sleep(sleep)
}

func readHTTPConnectRequestLine(t *testing.T, conn net.Conn) (string, bool) {
	t.Helper()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Errorf("failed reading CONNECT line: %v", err)
		return "", false
	}
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("failed reading header: %v", err)
			return "", false
		}
		if header == "\r\n" {
			break
		}
	}
	return line, true
}

func serveOneSOCKS5(t *testing.T, listener net.Listener) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Errorf("failed reading SOCKS5 greeting header: %v", err)
		return
	}
	if header[0] != 0x05 {
		t.Errorf("unexpected SOCKS version in greeting: %d", header[0])
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("failed reading SOCKS5 methods: %v", err)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		t.Errorf("failed writing SOCKS5 method select: %v", err)
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		t.Errorf("failed reading SOCKS5 request header: %v", err)
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		t.Errorf("unexpected SOCKS5 request header: %v", req)
		return
	}
	switch req[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16))
	default:
		t.Errorf("unexpected SOCKS5 atyp: %d", req[3])
		return
	}
	if err != nil {
		t.Errorf("failed reading SOCKS5 destination address: %v", err)
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Errorf("failed reading SOCKS5 destination port: %v", err)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Errorf("failed writing SOCKS5 success response: %v", err)
		return
	}
}

func serveOneSOCKS5RejectMethod(t *testing.T, listener net.Listener) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Errorf("failed reading SOCKS5 greeting header: %v", err)
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("failed reading SOCKS5 methods: %v", err)
		return
	}
	_, _ = conn.Write([]byte{0x05, 0xFF})
}

func serveOneSOCKS5ReplyFailure(t *testing.T, listener net.Listener, replyCode byte) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Errorf("failed reading SOCKS5 greeting header: %v", err)
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("failed reading SOCKS5 methods: %v", err)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		t.Errorf("failed writing SOCKS5 method select: %v", err)
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		t.Errorf("failed reading SOCKS5 request header: %v", err)
		return
	}
	switch req[3] {
	case 0x01:
		_, err = io.ReadFull(conn, make([]byte, 4))
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])))
		}
	case 0x04:
		_, err = io.ReadFull(conn, make([]byte, 16))
	default:
		return
	}
	if err != nil {
		t.Errorf("failed reading SOCKS5 destination address: %v", err)
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Errorf("failed reading SOCKS5 destination port: %v", err)
		return
	}
	_, _ = conn.Write([]byte{0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func serveOneSOCKS5ExpectDomainTarget(t *testing.T, listener net.Listener, wantHost string, wantPort uint16) {
	t.Helper()
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Errorf("failed reading SOCKS5 greeting header: %v", err)
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Errorf("failed reading SOCKS5 methods: %v", err)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		t.Errorf("failed writing SOCKS5 method select: %v", err)
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		t.Errorf("failed reading SOCKS5 request header: %v", err)
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 || req[3] != 0x03 {
		t.Errorf("unexpected SOCKS5 request header for domain target: %v", req)
		return
	}
	domainLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, domainLen); err != nil {
		t.Errorf("failed reading SOCKS5 domain length: %v", err)
		return
	}
	domain := make([]byte, int(domainLen[0]))
	if _, err := io.ReadFull(conn, domain); err != nil {
		t.Errorf("failed reading SOCKS5 domain: %v", err)
		return
	}
	if string(domain) != wantHost {
		t.Errorf("expected SOCKS5 domain %q, got %q", wantHost, string(domain))
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		t.Errorf("failed reading SOCKS5 destination port: %v", err)
		return
	}
	gotPort := uint16(portBuf[0])<<8 | uint16(portBuf[1])
	if gotPort != wantPort {
		t.Errorf("expected SOCKS5 port %d, got %d", wantPort, gotPort)
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Errorf("failed writing SOCKS5 success response: %v", err)
		return
	}
}
