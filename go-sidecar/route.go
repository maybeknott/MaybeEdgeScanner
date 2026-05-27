package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type RouteType string

const (
	RouteDirect      RouteType = "direct"
	RouteSOCKS5      RouteType = "socks5"
	RouteHTTPConnect RouteType = "http_connect"
)

type RouteConfig struct {
	RouteID          string
	Type             RouteType
	ProxyAddress     string
	Username         string
	Password         string
	DNSPolicy        string
	Timeout          time.Duration
	AllowPassword    bool
	ProviderID       string
	RouteBinding     string
	ProtocolMode     string
	AuthMode         string
	SplitTunnel      string
	UpstreamMode     string
	DownstreamMode   string
	ProxyGatewayMode string
}

type RouteObservation struct {
	RouteID          string
	RouteType        RouteType
	Target           string
	ProxyAddress     string
	DNSPolicy        string
	Status           string
	ProxyStatus      int
	ErrorCode        string
	Latency          time.Duration
	ProviderID       string
	RouteBinding     string
	ProtocolMode     string
	AuthMode         string
	SplitTunnel      string
	UpstreamMode     string
	DownstreamMode   string
	ProxyGatewayMode string
}

var errRouteValidation = errors.New("invalid route config")

func dialViaRoute(ctx context.Context, network, address string, cfg RouteConfig) (net.Conn, RouteObservation, error) {
	start := time.Now()
	obs := RouteObservation{
		RouteID:          cfg.RouteID,
		RouteType:        cfg.Type,
		Target:           address,
		ProxyAddress:     cfg.ProxyAddress,
		DNSPolicy:        cfg.DNSPolicy,
		Status:           "failed",
		ProviderID:       cfg.ProviderID,
		RouteBinding:     cfg.RouteBinding,
		ProtocolMode:     cfg.ProtocolMode,
		AuthMode:         cfg.AuthMode,
		SplitTunnel:      cfg.SplitTunnel,
		UpstreamMode:     cfg.UpstreamMode,
		DownstreamMode:   cfg.DownstreamMode,
		ProxyGatewayMode: cfg.ProxyGatewayMode,
	}
	finish := func(conn net.Conn, err error, code string) (net.Conn, RouteObservation, error) {
		obs.Latency = time.Since(start)
		if err == nil {
			obs.Status = "success"
			return conn, obs, nil
		}
		obs.ErrorCode = code
		return nil, obs, err
	}

	if err := validateRouteConfig(cfg); err != nil {
		return finish(nil, err, "INPUT_INVALID")
	}
	if err := validateDialAddress(address); err != nil {
		return finish(nil, err, "INPUT_INVALID")
	}

	switch cfg.Type {
	case RouteDirect:
		conn, err := dialDirect(ctx, network, address, cfg.Timeout)
		return finish(conn, err, "TCP_NETWORK_UNREACHABLE")
	case RouteHTTPConnect:
		conn, status, err := dialHTTPConnect(ctx, network, address, cfg)
		obs.ProxyStatus = status
		return finish(conn, err, classifyHTTPConnectError(status, err))
	case RouteSOCKS5:
		conn, err := dialSOCKS5(ctx, network, address, cfg)
		return finish(conn, err, "PROXY_CONNECT_REJECTED")
	default:
		return finish(nil, fmt.Errorf("%w: unsupported route type %q", errRouteValidation, cfg.Type), "INPUT_UNSUPPORTED_KIND")
	}
}

func validateRouteConfig(cfg RouteConfig) error {
	if strings.TrimSpace(cfg.RouteID) == "" {
		return fmt.Errorf("%w: route_id is required", errRouteValidation)
	}
	if containsCRLF(
		cfg.RouteID,
		cfg.ProxyAddress,
		cfg.Username,
		cfg.Password,
		cfg.DNSPolicy,
		cfg.ProviderID,
		cfg.RouteBinding,
		cfg.ProtocolMode,
		cfg.AuthMode,
		cfg.SplitTunnel,
		cfg.UpstreamMode,
		cfg.DownstreamMode,
		cfg.ProxyGatewayMode,
	) {
		return fmt.Errorf("%w: route fields must not contain CR/LF", errRouteValidation)
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("%w: timeout must be positive", errRouteValidation)
	}
	switch cfg.Type {
	case RouteDirect:
		return nil
	case RouteHTTPConnect, RouteSOCKS5:
		if strings.TrimSpace(cfg.ProxyAddress) == "" {
			return fmt.Errorf("%w: proxy address is required", errRouteValidation)
		}
		if cfg.Password != "" && !cfg.AllowPassword {
			return fmt.Errorf("%w: password requires explicit AllowPassword", errRouteValidation)
		}
		return validateDialAddress(cfg.ProxyAddress)
	default:
		return fmt.Errorf("%w: unsupported route type %q", errRouteValidation, cfg.Type)
	}
}

func validateDialAddress(address string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("%w: address is required", errRouteValidation)
	}
	if containsCRLF(address) {
		return fmt.Errorf("%w: address must not contain CR/LF", errRouteValidation)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: address must be host:port: %v", errRouteValidation, err)
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return fmt.Errorf("%w: address requires host and port", errRouteValidation)
	}
	return nil
}

func containsCRLF(values ...string) bool {
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") {
			return true
		}
	}
	return false
}

func dialDirect(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, network, address)
}

func dialHTTPConnect(ctx context.Context, network, target string, cfg RouteConfig) (net.Conn, int, error) {
	conn, err := dialDirect(ctx, network, cfg.ProxyAddress, cfg.Timeout)
	if err != nil {
		return nil, 0, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	}

	hostHeader := target
	if parsed, err := url.Parse("//" + target); err == nil && parsed.Host != "" {
		hostHeader = parsed.Host
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: MaybeScanner-Sidecar/route\r\n", target, hostHeader)
	if cfg.Username != "" || cfg.Password != "" {
		encoded := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		fmt.Fprintf(&builder, "Proxy-Authorization: Basic %s\r\n", encoded)
	}
	builder.WriteString("\r\n")
	if _, err := conn.Write([]byte(builder.String())); err != nil {
		return nil, 0, err
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, fmt.Errorf("proxy CONNECT rejected with status %d", response.StatusCode)
	}
	if err := rejectUnexpectedProxyHeaders(response.Header); err != nil {
		return nil, response.StatusCode, err
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	return conn, response.StatusCode, nil
}

func rejectUnexpectedProxyHeaders(header http.Header) error {
	for key, values := range header {
		canonical := textproto.CanonicalMIMEHeaderKey(key)
		for _, value := range values {
			if containsCRLF(canonical, value) {
				return fmt.Errorf("proxy header contains CR/LF")
			}
		}
	}
	return nil
}

func classifyHTTPConnectError(status int, err error) string {
	if err == nil {
		return ""
	}
	switch status {
	case http.StatusProxyAuthRequired:
		return "PROXY_AUTH_REQUIRED"
	case 0:
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return "PROXY_TIMEOUT"
		}
		return "PROXY_MALFORMED_RESPONSE"
	default:
		return "PROXY_CONNECT_REJECTED"
	}
}

func dialSOCKS5(ctx context.Context, network, target string, cfg RouteConfig) (net.Conn, error) {
	auth := &proxy.Auth{User: cfg.Username, Password: cfg.Password}
	if cfg.Username == "" && cfg.Password == "" {
		auth = nil
	}
	dialer, err := proxy.SOCKS5(network, cfg.ProxyAddress, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support context")
	}
	return contextDialer.DialContext(ctx, network, target)
}
