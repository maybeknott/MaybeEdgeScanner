package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPsiphonNoticeParserDetectsProxyReadiness(t *testing.T) {
	state, err := ParsePsiphonNoticeStream("route-psiphon", strings.NewReader(
		`{"notice_type":"ListeningSocksProxyPort","ListeningSocksProxyPort":1080}`+"\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "success" || state.ReadinessState != "proxy_listening" || state.SOCKSPort != 1080 {
		t.Fatalf("unexpected psiphon readiness: %#v", state)
	}
}

func TestWindscribeRouteObserverDetectsExternalVPNAndDNSDelta(t *testing.T) {
	observer := WindscribeRouteObserver{Connectivity: staticConnectivitySnapshotter{snapshot: ConnectivitySnapshot{
		ExternalIP:       "198.51.100.200",
		DNSResolvers:     []string{"10.255.0.1"},
		DefaultInterface: "tun0",
	}}}
	state, err := observer.Observe(context.Background(), RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe",
		PluginID:      "windscribe",
		ProfileRef:    "ref:profile",
		Fields: map[string]string{
			"mode":       "wireguard",
			"dns_policy": "ctrld",
		},
	}, ConnectivitySnapshot{
		ExternalIP:   "203.0.113.20",
		DNSResolvers: []string{"192.0.2.53"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "success" || !state.ExternalVPNObserved || state.DNSPolicyObserved != "ctrld" {
		t.Fatalf("unexpected windscribe observation: %#v", state)
	}
}

func TestProbeLocalHTTPProxyDetectsListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	state := ProbeLocalHTTPProxy(context.Background(), "http://"+ln.Addr().String(), time.Second)
	if state.Status != "success" || !state.LocalProxyObserved {
		t.Fatalf("unexpected local proxy state: %#v", state)
	}
	<-done
}
