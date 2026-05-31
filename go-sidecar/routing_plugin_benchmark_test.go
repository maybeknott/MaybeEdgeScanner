package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func BenchmarkRoutingPluginValidationWindscribe(b *testing.B) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		b.Fatal(err)
	}
	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-bench",
		PluginID:      "windscribe",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:windscribe-wireguard",
		CredentialRef: "ref:windscribe-session",
		Fields: map[string]string{
			"mode":            "wireguard",
			"auth_mode":       "wsnet_session_ref",
			"dns_policy":      "ctrld",
			"split_tunnel":    "scanner_app_only",
			"downstream_mode": "vpn_interface",
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := validateRoutingPluginConfig(registry, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoutingPluginValidationPsiphonConduitFronting(b *testing.B) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		b.Fatal(err)
	}
	cfg := RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-bench",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		ConfigRef:     "ref:psiphon-config",
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields: map[string]string{
			"mode":                    "tunnel_core_supervised",
			"route_strategy":          "conduit_first",
			"conduit_mode":            "auto",
			"conduit_timeout_seconds": "180",
			"beast_mode":              "true",
			"provider_chain":          "psiphon_over_windscribe",
			"chain_upstream_ref":      "ref:windscribe-route",
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := validateRoutingPluginConfig(registry, cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRouteObservationPreviewWindscribe(b *testing.B) {
	registry, _ := defaultRoutingPluginRegistry()
	plugin, _ := registry.Get("windscribe")
	cfg := RoutingPluginConfig{SchemaVersion: 1, RouteID: "route-bench", PluginID: "windscribe", ProfileRef: "ref:profile", Fields: map[string]string{"mode": "wireguard"}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = routeObservationPreview(plugin, cfg)
	}
}

func BenchmarkLocalProxyProbeLoopback(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	endpoint := "http://" + ln.Addr().String()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if state := ProbeLocalHTTPProxy(context.Background(), endpoint, time.Second); state.Status != "success" {
			b.Fatalf("unexpected state: %#v", state)
		}
	}
}

func BenchmarkRouteAttributionApplyToResult(b *testing.B) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		b.Fatal(err)
	}
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-attribution",
		PluginID:      "windscribe",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:windscribe-wireguard",
		CredentialRef: "ref:windscribe-session",
		Fields: map[string]string{
			"mode":            "wireguard",
			"auth_mode":       "wsnet_session_ref",
			"dns_policy":      "ctrld",
			"downstream_mode": "vpn_interface",
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	if !plan.Valid {
		b.Fatal("route plan is not valid")
	}
	// keep registry referenced so the benchmark setup mirrors real validation lifetime.
	_ = registry
	base := result{
		Target:                "198.51.100.12",
		IP:                    "198.51.100.12",
		Port:                  443,
		SNI:                   "edge.example.test",
		TCP:                   true,
		TLS:                   true,
		HTTP:                  true,
		NetworkClassification: "akamai",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row := base
		plan.ApplyRequestedToResult(&row)
		plan.ApplyRouteNotObserved(&row)
	}
}

func BenchmarkRouteAttributionApplyToResultBatch1K(b *testing.B) {
	plan, err := validateScanRoutePlugin(&RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-attribution",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		ConfigRef:     "ref:psiphon-config",
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields: map[string]string{
			"mode":           "tunnel_core_supervised",
			"route_strategy": "conduit_first",
			"conduit_mode":   "auto",
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	if !plan.Valid {
		b.Fatal("route plan is not valid")
	}
	const batchSize = 1024
	rows := make([]result, batchSize)
	for i := 0; i < batchSize; i++ {
		rows[i] = result{
			Target:                "203.0.113.10",
			IP:                    "203.0.113.10",
			Port:                  443,
			SNI:                   "scan.example.test",
			NetworkClassification: "cloudflare",
		}
	}
	b.ReportAllocs()
	b.SetBytes(batchSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < batchSize; j++ {
			plan.ApplyRequestedToResult(&rows[j])
			plan.ApplyRouteNotObserved(&rows[j])
		}
	}
}
