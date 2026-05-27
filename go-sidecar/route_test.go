package main

import (
	"bufio"
	"context"
	"fmt"
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
	if obs.ErrorCode != "PROXY_AUTH_REQUIRED" || obs.ProxyStatus != http.StatusProxyAuthRequired {
		t.Fatalf("unexpected observation: %+v", obs)
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
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Errorf("failed reading CONNECT line: %v", err)
		return
	}
	if !strings.HasPrefix(line, "CONNECT ") {
		t.Errorf("expected CONNECT request, got %q", line)
		return
	}
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("failed reading header: %v", err)
			return
		}
		if header == "\r\n" {
			break
		}
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}
