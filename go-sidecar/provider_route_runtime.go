package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProviderRouteReadiness struct {
	ProviderID           string            `json:"provider_id"`
	RouteID              string            `json:"route_id"`
	ProtocolMode         string            `json:"protocol_mode"`
	RouteBinding         string            `json:"route_binding"`
	RouteStrategy        string            `json:"route_strategy,omitempty"`
	ConduitMode          string            `json:"conduit_mode,omitempty"`
	ProviderChain        string            `json:"provider_chain,omitempty"`
	FrontingPolicy       string            `json:"fronting_policy,omitempty"`
	LANSharing           bool              `json:"lan_sharing,omitempty"`
	BeastMode            bool              `json:"beast_mode,omitempty"`
	ReadinessState       string            `json:"readiness_state"`
	Status               string            `json:"status"`
	SOCKSPort            int               `json:"socks_port,omitempty"`
	HTTPProxyPort        int               `json:"http_proxy_port,omitempty"`
	LANSOCKSPort         int               `json:"lan_socks_port,omitempty"`
	LANHTTPProxyPort     int               `json:"lan_http_proxy_port,omitempty"`
	ExternalVPNObserved  bool              `json:"external_vpn_observed,omitempty"`
	LocalProxyObserved   bool              `json:"local_proxy_observed,omitempty"`
	DNSPolicyObserved    string            `json:"dns_policy_observed,omitempty"`
	InterfaceHint        string            `json:"interface_hint,omitempty"`
	ErrorCode            string            `json:"error_code,omitempty"`
	Evidence             map[string]string `json:"evidence,omitempty"`
	LastTransitionUnixMS int64             `json:"last_transition_unix_ms"`
}

type PsiphonNoticeParser struct {
	readiness ProviderRouteReadiness
}

func NewPsiphonNoticeParser(routeID string) *PsiphonNoticeParser {
	return &PsiphonNoticeParser{readiness: ProviderRouteReadiness{
		ProviderID:           "psiphon",
		RouteID:              routeID,
		ProtocolMode:         "tunnel_core_supervised",
		RouteBinding:         "tunnel_core_local_proxy",
		RouteStrategy:        "auto",
		ConduitMode:          "auto",
		ReadinessState:       "starting",
		Status:               "starting",
		Evidence:             map[string]string{},
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}}
}

func (p *PsiphonNoticeParser) ParseLine(line string) ProviderRouteReadiness {
	line = strings.TrimSpace(line)
	if p.readiness.Evidence == nil {
		p.readiness.Evidence = map[string]string{}
	}
	p.readiness.LastTransitionUnixMS = time.Now().UnixMilli()
	if containsCRLF(line) {
		p.readiness.Status = "failed"
		p.readiness.ReadinessState = "failed"
		p.readiness.ErrorCode = "INPUT_INVALID"
		return p.readiness
	}
	if strings.HasPrefix(line, "{") {
		var notice map[string]any
		if err := json.Unmarshal([]byte(line), &notice); err == nil {
			p.applyPsiphonNoticeMap(notice)
			return p.readiness
		}
	}
	p.applyPsiphonNoticeText(line)
	return p.readiness
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeMap(notice map[string]any) {
	for key, value := range notice {
		switch strings.ToLower(key) {
		case "listeningsocksproxyport", "listening_socks_proxy_port", "socks_port":
			p.readiness.SOCKSPort = intFromAny(value)
		case "listeninghttpproxyport", "listening_http_proxy_port", "http_proxy_port":
			p.readiness.HTTPProxyPort = intFromAny(value)
		case "event_name", "notice_type", "type":
			p.readiness.Evidence["last_notice"] = fmt.Sprint(value)
		case "tunnels", "tunnels.count":
			p.readiness.Evidence["tunnels"] = fmt.Sprint(value)
		case "shareproxyonnetwork", "share_proxy_on_network", "lan_sharing":
			p.readiness.LANSharing = boolFromAny(value)
		case "shareproxyonnetworksocksport", "lan_socks_port":
			p.readiness.LANSOCKSPort = intFromAny(value)
		case "shareproxyonnetworkhttpport", "lan_http_proxy_port":
			p.readiness.LANHTTPProxyPort = intFromAny(value)
		case "protocolselection", "route_strategy":
			p.readiness.RouteStrategy = strings.ToLower(fmt.Sprint(value))
		case "conduitmode", "conduit_mode":
			p.readiness.ConduitMode = strings.ToLower(fmt.Sprint(value))
		case "beastmode", "beast_mode":
			p.readiness.BeastMode = boolFromAny(value)
		}
	}
	p.updatePsiphonReady()
}

func (p *PsiphonNoticeParser) applyPsiphonNoticeText(line string) {
	lower := strings.ToLower(line)
	p.readiness.Evidence["last_notice"] = truncateEvidence(line, 180)
	for _, token := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	}) {
		parts := strings.SplitN(token, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.Trim(parts[0], `"'`))
		value := strings.Trim(parts[1], `"'`)
		if key == "listeningsocksproxyport" || key == "socks_port" {
			p.readiness.SOCKSPort, _ = strconv.Atoi(value)
		}
		if key == "listeninghttpproxyport" || key == "http_proxy_port" {
			p.readiness.HTTPProxyPort, _ = strconv.Atoi(value)
		}
		if key == "shareproxyonnetwork" || key == "lan_sharing" {
			p.readiness.LANSharing = strings.EqualFold(value, "true")
		}
		if key == "shareproxyonnetworksocksport" || key == "lan_socks_port" {
			p.readiness.LANSOCKSPort, _ = strconv.Atoi(value)
		}
		if key == "shareproxyonnetworkhttpport" || key == "lan_http_proxy_port" {
			p.readiness.LANHTTPProxyPort, _ = strconv.Atoi(value)
		}
	}
	if strings.Contains(lower, "conduit") {
		p.readiness.RouteStrategy = "conduit"
	}
	if strings.Contains(lower, "cdn_fronting") || strings.Contains(lower, "fronting") {
		p.readiness.FrontingPolicy = "cdn_fronting"
	}
	if strings.Contains(lower, "beast") {
		p.readiness.BeastMode = true
	}
	if strings.Contains(lower, "tunnel") || strings.Contains(lower, "listening") {
		p.updatePsiphonReady()
	}
}

func (p *PsiphonNoticeParser) updatePsiphonReady() {
	if p.readiness.SOCKSPort > 0 || p.readiness.HTTPProxyPort > 0 {
		p.readiness.ReadinessState = "proxy_listening"
		p.readiness.Status = "success"
		p.readiness.ErrorCode = ""
		return
	}
	p.readiness.ReadinessState = "starting"
	p.readiness.Status = "starting"
}

func ParsePsiphonNoticeStream(routeID string, reader io.Reader) (ProviderRouteReadiness, error) {
	parser := NewPsiphonNoticeParser(routeID)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	var state ProviderRouteReadiness
	for scanner.Scan() {
		state = parser.ParseLine(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return state, err
	}
	return state, nil
}

type WindscribeRouteObserver struct {
	Connectivity ConnectivitySnapshotter
}

type ConnectivitySnapshotter interface {
	Snapshot(ctx context.Context) (ConnectivitySnapshot, error)
}

type ConnectivitySnapshot struct {
	ExternalIP       string
	DNSResolvers     []string
	Interfaces       []string
	DefaultInterface string
	HTTPProxy        string
	SOCKSProxy       string
}

func (o WindscribeRouteObserver) Observe(ctx context.Context, cfg RoutingPluginConfig, baseline ConnectivitySnapshot) (ProviderRouteReadiness, error) {
	if o.Connectivity == nil {
		return ProviderRouteReadiness{}, errors.New("connectivity snapshotter is required")
	}
	current, err := o.Connectivity.Snapshot(ctx)
	state := ProviderRouteReadiness{
		ProviderID:           "windscribe",
		RouteID:              cfg.RouteID,
		ProtocolMode:         normalizedProtocolMode(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg),
		RouteBinding:         routeBindingForPlugin(RoutingPluginDescriptor{PluginID: "windscribe", PluginType: "windscribe", RouteType: "plugin"}, cfg),
		RouteStrategy:        normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg),
		ProviderChain:        normalizedProviderChain(cfg),
		LANSharing:           lanSharingEnabled(cfg),
		ReadinessState:       "not_checked",
		Status:               "failed",
		DNSPolicyObserved:    normalizedField(cfg, "dns_policy", "system_or_route_default"),
		InterfaceHint:        current.DefaultInterface,
		Evidence:             map[string]string{},
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}
	if err != nil {
		state.ErrorCode = "TCP_NETWORK_UNREACHABLE"
		return state, err
	}
	state.ExternalVPNObserved = baseline.ExternalIP != "" && current.ExternalIP != "" && baseline.ExternalIP != current.ExternalIP
	state.DNSPolicyObserved = observeDNSPolicy(cfg, baseline, current)
	if state.RouteBinding == "local_proxy_gateway" {
		state.LocalProxyObserved = current.HTTPProxy != "" || current.SOCKSProxy != ""
	}
	state.Evidence["baseline_external_ip_present"] = strconv.FormatBool(baseline.ExternalIP != "")
	state.Evidence["current_external_ip_present"] = strconv.FormatBool(current.ExternalIP != "")
	state.Evidence["dns_resolver_delta"] = strconv.FormatBool(!stringSlicesEqual(baseline.DNSResolvers, current.DNSResolvers))
	if state.ExternalVPNObserved || state.LocalProxyObserved || normalizedProtocolMode(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg) != "external_vpn" {
		state.ReadinessState = "probe_passed"
		state.Status = "success"
		return state, nil
	}
	state.ReadinessState = "degraded"
	state.Status = "failed"
	state.ErrorCode = "PLUGIN_ROUTE_NOT_READY"
	return state, nil
}

func observeDNSPolicy(cfg RoutingPluginConfig, baseline, current ConnectivitySnapshot) string {
	policy := normalizedField(cfg, "dns_policy", "system_or_route_default")
	if policy == "no_dns" {
		return "no_dns"
	}
	if !stringSlicesEqual(baseline.DNSResolvers, current.DNSResolvers) {
		return policy
	}
	return "system_or_route_default"
}

func ProbeLocalHTTPProxy(ctx context.Context, endpoint string, timeout time.Duration) ProviderRouteReadiness {
	start := time.Now()
	state := ProviderRouteReadiness{
		ProviderID:           "windscribe",
		RouteBinding:         "local_proxy_gateway",
		ReadinessState:       "not_checked",
		Status:               "failed",
		LastTransitionUnixMS: time.Now().UnixMilli(),
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		state.ErrorCode = "INPUT_INVALID"
		return state
	}
	parsed, _ := url.Parse(endpoint)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", parsed.Host)
	if err != nil {
		state.ErrorCode = "PROXY_TIMEOUT"
		return state
	}
	_ = conn.Close()
	state.LocalProxyObserved = true
	state.ReadinessState = "proxy_listening"
	state.Status = "success"
	state.Evidence = map[string]string{"latency_ms": strconv.FormatInt(time.Since(start).Milliseconds(), 10)}
	return state
}

type staticConnectivitySnapshotter struct {
	snapshot ConnectivitySnapshot
	err      error
}

func (s staticConnectivitySnapshotter) Snapshot(context.Context) (ConnectivitySnapshot, error) {
	return s.snapshot, s.err
}

func intFromAny(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}

func boolFromAny(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func truncateEvidence(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
