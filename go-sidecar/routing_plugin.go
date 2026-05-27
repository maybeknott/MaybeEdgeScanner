package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type RoutingPluginDescriptor struct {
	SchemaVersion     int      `json:"schema_version"`
	PluginID          string   `json:"plugin_id"`
	PluginType        string   `json:"plugin_type"`
	DisplayName       string   `json:"display_name"`
	Version           string   `json:"version"`
	SourceURL         string   `json:"source_url"`
	License           string   `json:"license"`
	RouteType         string   `json:"route_type"`
	CredentialMode    string   `json:"credential_mode"`
	LocalAPIMode      string   `json:"local_api_mode"`
	LocalAPIRequired  bool     `json:"local_api_required"`
	SecretPolicy      string   `json:"secret_policy"`
	Enabled           bool     `json:"enabled"`
	EnabledByDefault  bool     `json:"enabled_by_default"`
	SupportsIPv4      bool     `json:"supports_ipv4"`
	SupportsIPv6      bool     `json:"supports_ipv6"`
	SupportsRemoteDNS bool     `json:"supports_remote_dns"`
	DiagnosticLabel   string   `json:"diagnostic_label"`
	RedactedFields    []string `json:"redacted_fields,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

type RoutingPluginRegistry struct {
	descriptors map[string]RoutingPluginDescriptor
}

type RoutingPluginConfig struct {
	SchemaVersion int               `json:"schema_version"`
	RouteID       string            `json:"route_id"`
	PluginID      string            `json:"plugin_id"`
	Enabled       bool              `json:"enabled"`
	RemoteDNS     bool              `json:"remote_dns"`
	Endpoint      string            `json:"endpoint,omitempty"`
	LocalAPIURL   string            `json:"local_api_url,omitempty"`
	CredentialRef string            `json:"credential_ref,omitempty"`
	ConfigRef     string            `json:"config_ref,omitempty"`
	ProfileRef    string            `json:"profile_ref,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type RoutingPluginConfigValidation struct {
	Valid          bool                    `json:"valid"`
	RouteID        string                  `json:"route_id"`
	PluginID       string                  `json:"plugin_id"`
	PluginType     string                  `json:"plugin_type"`
	RouteType      string                  `json:"route_type"`
	RemoteDNS      bool                    `json:"remote_dns"`
	AuthMode       string                  `json:"auth_mode,omitempty"`
	ProtocolMode   string                  `json:"protocol_mode,omitempty"`
	DNSPolicy      string                  `json:"dns_policy,omitempty"`
	SplitTunnel    string                  `json:"split_tunnel,omitempty"`
	UpstreamMode   string                  `json:"upstream_mode,omitempty"`
	DownstreamMode string                  `json:"downstream_mode,omitempty"`
	RouteBinding   string                  `json:"route_binding,omitempty"`
	RouteStrategy  string                  `json:"route_strategy,omitempty"`
	ConduitMode    string                  `json:"conduit_mode,omitempty"`
	ProviderChain  string                  `json:"provider_chain,omitempty"`
	FrontingPolicy string                  `json:"fronting_policy,omitempty"`
	LANSharing     bool                    `json:"lan_sharing"`
	BeastMode      bool                    `json:"beast_mode"`
	DryRunOnly     bool                    `json:"dry_run_only"`
	Attachable     bool                    `json:"attachable"`
	ReadinessProbe string                  `json:"readiness_probe,omitempty"`
	Capabilities   []string                `json:"capabilities,omitempty"`
	Components     []string                `json:"components,omitempty"`
	Observations   []string                `json:"observations,omitempty"`
	Observation    RouteObservationPreview `json:"observation_template"`
	RedactedConfig map[string]string       `json:"redacted_config"`
	Warnings       []string                `json:"warnings,omitempty"`
	Descriptor     RoutingPluginDescriptor `json:"descriptor"`
}

type RouteObservationPreview struct {
	SchemaVersion      int            `json:"schema_version"`
	ObservationID      string         `json:"observation_id"`
	RouteID            string         `json:"route_id"`
	RouteType          string         `json:"route_type"`
	RouteBinding       string         `json:"route_binding"`
	NetworkPath        string         `json:"network_path"`
	ProviderID         *string        `json:"provider_id"`
	ProtocolMode       *string        `json:"protocol_mode"`
	AuthMode           *string        `json:"auth_mode"`
	DNSPolicy          string         `json:"dns_policy"`
	RemoteDNSRequested bool           `json:"remote_dns_requested"`
	RemoteDNSObserved  *bool          `json:"remote_dns_observed"`
	SplitTunnel        *string        `json:"split_tunnel"`
	UpstreamMode       *string        `json:"upstream_mode"`
	DownstreamMode     *string        `json:"downstream_mode"`
	ProxyGatewayMode   *string        `json:"proxy_gateway_mode"`
	RouteStrategy      *string        `json:"route_strategy,omitempty"`
	ConduitMode        *string        `json:"conduit_mode,omitempty"`
	ProviderChain      *string        `json:"provider_chain,omitempty"`
	FrontingPolicy     *string        `json:"fronting_policy,omitempty"`
	LANSharing         bool           `json:"lan_sharing,omitempty"`
	BeastMode          bool           `json:"beast_mode,omitempty"`
	ReadinessState     string         `json:"readiness_state"`
	Status             string         `json:"status"`
	LatencyMS          float64        `json:"latency_ms"`
	ErrorCode          *string        `json:"error_code"`
	Evidence           map[string]any `json:"evidence"`
}

var errPluginDescriptor = errors.New("invalid routing plugin descriptor")
var errPluginConfig = errors.New("invalid routing plugin config")

func defaultRoutingPluginRegistry() (*RoutingPluginRegistry, error) {
	descriptors := []RoutingPluginDescriptor{
		{
			SchemaVersion:    1,
			PluginID:         "generic-proxy",
			PluginType:       "generic_proxy",
			DisplayName:      "Generic proxy route",
			Version:          "adapter-v1",
			SourceURL:        "local://generic-proxy",
			License:          "app-native",
			RouteType:        "socks5",
			CredentialMode:   "user_supplied",
			LocalAPIMode:     "none",
			LocalAPIRequired: false,
			SecretPolicy:     "credential_ref_only",
			Enabled:          true,
			EnabledByDefault: true,
			SupportsIPv4:     true, SupportsIPv6: true, SupportsRemoteDNS: true,
			DiagnosticLabel: "Generic SOCKS/HTTP proxy",
			RedactedFields:  []string{"username", "password", "proxy_authorization"},
			Notes:           []string{"Credentials are references only and must not be logged"},
		},
		{
			SchemaVersion:    1,
			PluginID:         "psiphon",
			PluginType:       "psiphon",
			DisplayName:      "Psiphon route adapter",
			Version:          "adapter-v1",
			SourceURL:        "https://github.com/Psiphon-Labs/psiphon-tunnel-core",
			License:          "GPL-3.0-family",
			RouteType:        "plugin",
			CredentialMode:   "imported_config_ref",
			LocalAPIMode:     "none",
			LocalAPIRequired: false,
			SecretPolicy:     "imported_config_ref",
			Enabled:          true,
			EnabledByDefault: false,
			SupportsIPv4:     true, SupportsIPv6: false, SupportsRemoteDNS: true,
			DiagnosticLabel: "Psiphon plugin route",
			RedactedFields:  []string{"client_secret", "client_config", "authorization", "proxy_password"},
			Notes:           []string{"Edge-only adapter", "Matches Se7en-Pro style tunnel-core supervision: imported config, local SOCKS/HTTP proxy readiness, process diagnostics", "No embedded provider secret"},
		},
		{
			SchemaVersion:    1,
			PluginID:         "windscribe",
			PluginType:       "windscribe",
			DisplayName:      "Windscribe route adapter",
			Version:          "adapter-v1",
			SourceURL:        "https://windscribe.com/",
			License:          "external-provider-profile",
			RouteType:        "plugin",
			CredentialMode:   "user_supplied",
			LocalAPIMode:     "external_app",
			LocalAPIRequired: false,
			SecretPolicy:     "credential_ref_only",
			Enabled:          true,
			EnabledByDefault: false,
			SupportsIPv4:     true, SupportsIPv6: true, SupportsRemoteDNS: true,
			DiagnosticLabel: "Windscribe profile route",
			RedactedFields:  []string{"username", "password", "api_token", "session_auth_hash", "auth_hash", "secure_token", "captcha_solution", "wireguard_private_key", "openvpn_password"},
			Notes:           []string{"Edge-only adapter", "Absorb Windscribe as route capabilities: external VPN, local proxy gateway, OpenVPN UDP/TCP, Stealth, WSTunnel, WireGuard, IKEv2, DNS/ControlD/R.O.B.E.R.T policy, split tunnel policy, and wsnet-backed session references", "Windscribe public Android architecture routes API calls through wsnet; direct raw account API calls intentionally stay outside the Go sidecar boundary"},
		},
	}
	return NewRoutingPluginRegistry(descriptors)
}

func NewRoutingPluginRegistry(descriptors []RoutingPluginDescriptor) (*RoutingPluginRegistry, error) {
	reg := &RoutingPluginRegistry{descriptors: map[string]RoutingPluginDescriptor{}}
	for _, descriptor := range descriptors {
		if err := validateRoutingPluginDescriptor(descriptor); err != nil {
			return nil, err
		}
		if _, exists := reg.descriptors[descriptor.PluginID]; exists {
			return nil, fmt.Errorf("%w: duplicate plugin_id %q", errPluginDescriptor, descriptor.PluginID)
		}
		reg.descriptors[descriptor.PluginID] = descriptor
	}
	return reg, nil
}

func validateRoutingPluginDescriptor(d RoutingPluginDescriptor) error {
	if d.SchemaVersion != 1 {
		return fmt.Errorf("%w: unsupported schema_version %d", errPluginDescriptor, d.SchemaVersion)
	}
	required := []string{d.PluginID, d.PluginType, d.DisplayName, d.Version, d.SourceURL, d.License, d.RouteType, d.CredentialMode, d.LocalAPIMode, d.SecretPolicy, d.DiagnosticLabel}
	if containsCRLF(required...) {
		return fmt.Errorf("%w: descriptor strings must not contain CR/LF", errPluginDescriptor)
	}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: required descriptor field is empty", errPluginDescriptor)
		}
	}
	if d.EnabledByDefault && !d.Enabled {
		return fmt.Errorf("%w: enabled_by_default requires enabled", errPluginDescriptor)
	}
	if !allowedValue(d.PluginType, "generic_proxy", "psiphon", "windscribe") {
		return fmt.Errorf("%w: unsupported plugin_type %q", errPluginDescriptor, d.PluginType)
	}
	if !allowedValue(d.RouteType, "socks5", "http_connect", "plugin", "vpn") {
		return fmt.Errorf("%w: unsupported route_type %q", errPluginDescriptor, d.RouteType)
	}
	if !allowedValue(d.CredentialMode, "none", "user_supplied", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported credential_mode %q", errPluginDescriptor, d.CredentialMode)
	}
	if !allowedValue(d.LocalAPIMode, "none", "authenticated_http", "authenticated_unix_socket", "external_app") {
		return fmt.Errorf("%w: unsupported local_api_mode %q", errPluginDescriptor, d.LocalAPIMode)
	}
	if !allowedValue(d.SecretPolicy, "none", "credential_ref_only", "imported_config_ref", "external_app") {
		return fmt.Errorf("%w: unsupported secret_policy %q", errPluginDescriptor, d.SecretPolicy)
	}
	if d.LocalAPIRequired && d.LocalAPIMode == "none" {
		return fmt.Errorf("%w: local_api_required cannot use local_api_mode=none", errPluginDescriptor)
	}
	if d.PluginType == "psiphon" && d.SecretPolicy != "imported_config_ref" {
		return fmt.Errorf("%w: psiphon must use imported_config_ref secret policy", errPluginDescriptor)
	}
	if d.PluginType == "windscribe" && d.SecretPolicy != "credential_ref_only" {
		return fmt.Errorf("%w: windscribe must use credential_ref_only secret policy", errPluginDescriptor)
	}
	return nil
}

func allowedValue(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func (r *RoutingPluginRegistry) List() []RoutingPluginDescriptor {
	out := make([]RoutingPluginDescriptor, 0, len(r.descriptors))
	for _, descriptor := range r.descriptors {
		out = append(out, descriptor)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PluginID < out[j].PluginID })
	return out
}

func (r *RoutingPluginRegistry) Get(pluginID string) (RoutingPluginDescriptor, bool) {
	descriptor, ok := r.descriptors[pluginID]
	return descriptor, ok
}

func redactPluginDiagnostics(plugin RoutingPluginDescriptor, fields map[string]string) map[string]string {
	redacted := make(map[string]string, len(fields))
	secretNames := map[string]bool{}
	for _, field := range plugin.RedactedFields {
		secretNames[strings.ToLower(field)] = true
	}
	for key, value := range fields {
		lower := strings.ToLower(key)
		if secretNames[lower] || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "authorization") || strings.Contains(lower, "private_key") {
			redacted[key] = "[REDACTED]"
		} else {
			redacted[key] = value
		}
	}
	return redacted
}

func validateRoutingPluginConfig(registry *RoutingPluginRegistry, cfg RoutingPluginConfig) (RoutingPluginConfigValidation, error) {
	if cfg.SchemaVersion != 1 {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unsupported schema_version %d", errPluginConfig, cfg.SchemaVersion)
	}
	if containsCRLF(cfg.RouteID, cfg.PluginID, cfg.Endpoint, cfg.LocalAPIURL, cfg.CredentialRef, cfg.ConfigRef, cfg.ProfileRef) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: config strings must not contain CR/LF", errPluginConfig)
	}
	if err := validatePluginFieldMap(cfg.Fields); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if strings.TrimSpace(cfg.RouteID) == "" || strings.TrimSpace(cfg.PluginID) == "" {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: route_id and plugin_id are required", errPluginConfig)
	}
	plugin, ok := registry.Get(cfg.PluginID)
	if !ok {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: unknown plugin_id %q", errPluginConfig, cfg.PluginID)
	}
	if !plugin.Enabled {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q is not available in this build", errPluginConfig, cfg.PluginID)
	}
	if err := validateProviderFieldAllowlist(plugin, cfg); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	if cfg.RemoteDNS && !plugin.SupportsRemoteDNS {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q does not support remote DNS", errPluginConfig, cfg.PluginID)
	}
	if cfg.PluginID == "generic-proxy" {
		if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
			return RoutingPluginConfigValidation{}, err
		}
	}
	if plugin.PluginType == "psiphon" {
		if err := validatePsiphonMode(cfg); err != nil {
			return RoutingPluginConfigValidation{}, err
		}
	}
	if plugin.PluginType == "windscribe" {
		if err := validateWindscribeMode(cfg); err != nil {
			return RoutingPluginConfigValidation{}, err
		}
	}
	if plugin.LocalAPIRequired && !isLocalPluginAPI(cfg.LocalAPIURL) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: plugin %q requires localhost local_api_url", errPluginConfig, cfg.PluginID)
	}
	if leaksInlineSecret(plugin, cfg) {
		return RoutingPluginConfigValidation{}, fmt.Errorf("%w: inline secret detected; use credential_ref/config_ref/profile_ref", errPluginConfig)
	}
	redacted := map[string]string{
		"route_id":       cfg.RouteID,
		"plugin_id":      cfg.PluginID,
		"endpoint":       cfg.Endpoint,
		"local_api_url":  cfg.LocalAPIURL,
		"credential_ref": cfg.CredentialRef,
		"config_ref":     cfg.ConfigRef,
		"profile_ref":    cfg.ProfileRef,
	}
	for key, value := range cfg.Fields {
		redacted[key] = value
	}
	redacted = redactPluginDiagnostics(plugin, redacted)
	warnings := []string{}
	if plugin.PluginType == "psiphon" {
		warnings = append(warnings,
			"psiphon adapter is Edge-only; standard mode is tunnel-core/library supervision with operator-supplied config reference",
			"external Psiphon APK/VPN mode can only label and test a user-connected route unless a documented control API exists",
			"conduit/CDN-fronting/beast-mode fields are route establishment policy inputs and must be verified by notices, proxy readiness, and scan attribution",
			"validated config is dry-run/readiness input until route attachment is enabled in scan requests",
		)
	}
	if plugin.PluginType == "windscribe" {
		warnings = append(warnings,
			"windscribe adapter is Edge-only and expects user-owned external VPN/proxy/OpenVPN/WireGuard profile references",
			"Windscribe account login/session state remains Android-owned; Go receives only profile/session refs and route capabilities",
			"provider chaining such as psiphon_over_windscribe or windscribe_over_psiphon requires explicit upstream route refs",
			"validated config is dry-run/readiness input until route attachment is enabled in scan requests",
		)
	}
	readinessProbe := readinessProbeForPlugin(plugin, cfg)
	caps := pluginCapabilities(plugin, cfg)
	observation := routeObservationPreview(plugin, cfg)
	if err := validateRouteObservationTemplate(observation); err != nil {
		return RoutingPluginConfigValidation{}, err
	}
	return RoutingPluginConfigValidation{
		Valid:          true,
		RouteID:        cfg.RouteID,
		PluginID:       cfg.PluginID,
		PluginType:     plugin.PluginType,
		RouteType:      plugin.RouteType,
		RemoteDNS:      cfg.RemoteDNS,
		AuthMode:       normalizedAuthMode(plugin, cfg),
		ProtocolMode:   normalizedProtocolMode(plugin, cfg),
		DNSPolicy:      normalizedField(cfg, "dns_policy", "system_or_route_default"),
		SplitTunnel:    normalizedField(cfg, "split_tunnel", "scanner_app_only"),
		UpstreamMode:   normalizedField(cfg, "upstream_mode", "none"),
		DownstreamMode: normalizedField(cfg, "downstream_mode", "scanner_to_route"),
		RouteBinding:   routeBindingForPlugin(plugin, cfg),
		RouteStrategy:  normalizedRouteStrategy(plugin, cfg),
		ConduitMode:    normalizedConduitMode(cfg),
		ProviderChain:  normalizedProviderChain(cfg),
		FrontingPolicy: normalizedFrontingPolicy(cfg),
		LANSharing:     lanSharingEnabled(cfg),
		BeastMode:      beastModeEnabled(cfg),
		DryRunOnly:     true,
		Attachable:     false,
		ReadinessProbe: readinessProbe,
		Capabilities:   caps,
		Components:     providerComponents(plugin, cfg),
		Observations:   routeObservations(plugin, cfg),
		Observation:    observation,
		RedactedConfig: redacted,
		Warnings:       warnings,
		Descriptor:     plugin,
	}, nil
}

func validatePluginFieldMap(fields map[string]string) error {
	const maxPluginFields = 64
	const maxPluginFieldKeyBytes = 96
	const maxPluginFieldValueBytes = 4096
	if len(fields) > maxPluginFields {
		return fmt.Errorf("%w: too many provider fields", errPluginConfig)
	}
	for key, value := range fields {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			return fmt.Errorf("%w: provider field key is required", errPluginConfig)
		}
		if key != trimmedKey {
			return fmt.Errorf("%w: provider field keys must not have surrounding whitespace", errPluginConfig)
		}
		if key != strings.ToLower(key) {
			return fmt.Errorf("%w: provider field keys must be lowercase", errPluginConfig)
		}
		if len(key) > maxPluginFieldKeyBytes {
			return fmt.Errorf("%w: provider field key is too long", errPluginConfig)
		}
		if len(value) > maxPluginFieldValueBytes {
			return fmt.Errorf("%w: provider field value for %q is too long", errPluginConfig, key)
		}
		if containsCRLF(key, value) {
			return fmt.Errorf("%w: provider fields must not contain CR/LF", errPluginConfig)
		}
		if strings.ContainsAny(key, "\x00\t ") || !isPluginFieldKey(key) {
			return fmt.Errorf("%w: provider field key %q is invalid", errPluginConfig, key)
		}
	}
	return nil
}

func isPluginFieldKey(key string) bool {
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validateProviderFieldAllowlist(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) error {
	allowed := map[string]bool{
		"mode":                 true,
		"auth_mode":            true,
		"dns_policy":           true,
		"dns_ref":              true,
		"split_tunnel":         true,
		"upstream_mode":        true,
		"upstream_proxy_ref":   true,
		"downstream_mode":      true,
		"proxy_gateway_scope":  true,
		"gateway_auth_ref":     true,
		"local_socks_port":     true,
		"local_http_port":      true,
		"lan_socks_port":       true,
		"lan_http_port":        true,
		"share_proxy_on_lan":   true,
		"route_strategy":       true,
		"provider_chain":       true,
		"chain_upstream_ref":   true,
		"chain_downstream_ref": true,
	}
	switch plugin.PluginType {
	case "psiphon":
		for _, key := range []string{
			"package_name",
			"route_strategy",
			"protocol_selection",
			"conduit_mode",
			"conduit_timeout_seconds",
			"reject_censored_country_proxies",
			"conduit_fallback_to_public",
			"fronting_ip_ref",
			"cdn_fronting_ip_ref",
			"fronting_sni",
			"cdn_fronting_sni",
			"beast_mode",
			"establishment_intensity",
			"sponsor_id_ref",
			"device_location_ref",
			"client_secret",
			"region",
		} {
			allowed[key] = true
		}
	case "windscribe":
		for _, key := range []string{
			"route_strategy",
			"profile_type",
			"location_ref",
			"static_ip_ref",
			"port_forward_ref",
			"package_name",
			"session_ref",
			"api_profile_ref",
			"robert_policy_ref",
			"ctrld_profile_ref",
		} {
			allowed[key] = true
		}
	case "generic_proxy":
		// Common route policy fields plus mode/auth are enough for generic local proxy.
	default:
		return fmt.Errorf("%w: unsupported plugin type %q", errPluginConfig, plugin.PluginType)
	}
	for key := range cfg.Fields {
		if !allowed[strings.ToLower(key)] {
			return fmt.Errorf("%w: provider field %q is not supported for %s", errPluginConfig, key, plugin.PluginID)
		}
	}
	return nil
}

func leaksInlineSecret(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) bool {
	fields := map[string]string{}
	for key, value := range cfg.Fields {
		fields[key] = value
	}
	fields["credential_ref"] = cfg.CredentialRef
	fields["config_ref"] = cfg.ConfigRef
	fields["profile_ref"] = cfg.ProfileRef
	fields["endpoint"] = cfg.Endpoint
	for key, value := range fields {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ref") {
			continue
		}
		if value == "" {
			continue
		}
		if isSecretField(plugin, lower) && !strings.HasPrefix(value, "ref:") {
			return true
		}
	}
	return false
}

func isSecretField(plugin RoutingPluginDescriptor, lower string) bool {
	for _, field := range plugin.RedactedFields {
		if strings.ToLower(field) == lower {
			return true
		}
	}
	return strings.Contains(lower, "secret") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "private_key")
}

func isLocalPluginAPI(value string) bool {
	_, err := parseLocalPluginAPI(value)
	return err == nil
}

func parseLocalPluginAPI(value string) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: local_api_url is required", errPluginConfig)
	}
	if containsCRLF(value) {
		return nil, fmt.Errorf("%w: local_api_url must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid local_api_url: %v", errPluginConfig, err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%w: local_api_url must not contain credentials, query, or fragment", errPluginConfig)
	}
	switch parsed.Scheme {
	case "http":
		host := parsed.Hostname()
		port := parsed.Port()
		if !isLoopbackHost(host) || !validPort(port) {
			return nil, fmt.Errorf("%w: local_api_url must use loopback host and numeric port", errPluginConfig)
		}
	case "unix":
		if strings.TrimSpace(parsed.Path) == "" {
			return nil, fmt.Errorf("%w: unix local_api_url requires an app-private socket path", errPluginConfig)
		}
	default:
		return nil, fmt.Errorf("%w: local_api_url scheme must be http or unix", errPluginConfig)
	}
	return parsed, nil
}

func validateProxyEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return fmt.Errorf("%w: generic proxy endpoint is required", errPluginConfig)
	}
	if containsCRLF(endpoint) {
		return fmt.Errorf("%w: endpoint must not contain CR/LF", errPluginConfig)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%w: invalid proxy endpoint: %v", errPluginConfig, err)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: endpoint must not contain inline credentials", errPluginConfig)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%w: proxy endpoint must not contain path, query, or fragment", errPluginConfig)
	}
	if !allowedValue(parsed.Scheme, "socks5", "http", "http-connect") {
		return fmt.Errorf("%w: proxy endpoint scheme must be socks5, http, or http-connect", errPluginConfig)
	}
	if strings.TrimSpace(parsed.Hostname()) == "" || !validPort(parsed.Port()) {
		return fmt.Errorf("%w: proxy endpoint must include host and numeric port", errPluginConfig)
	}
	return nil
}

func validatePsiphonMode(cfg RoutingPluginConfig) error {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode == "" {
		mode = "tunnel_core_supervised"
	}
	if !allowedValue(mode, "tunnel_core_supervised", "tunnel_core_library", "external_vpn_apk", "external_vpn") {
		return fmt.Errorf("%w: unsupported psiphon mode %q", errPluginConfig, mode)
	}
	switch mode {
	case "tunnel_core_supervised", "tunnel_core_library":
		if strings.TrimSpace(cfg.ConfigRef) == "" {
			return fmt.Errorf("%w: psiphon tunnel-core mode requires config_ref, not inline ClientSecret/config data", errPluginConfig)
		}
		if strings.TrimSpace(cfg.Endpoint) != "" {
			if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
				return err
			}
		}
		if strings.TrimSpace(cfg.LocalAPIURL) != "" {
			if _, err := parseLocalPluginAPI(cfg.LocalAPIURL); err != nil {
				return err
			}
		}
	case "external_vpn_apk", "external_vpn":
		if strings.TrimSpace(cfg.ProfileRef) == "" && strings.TrimSpace(cfg.Fields["package_name"]) == "" {
			return fmt.Errorf("%w: psiphon external APK/VPN mode requires profile_ref or package_name", errPluginConfig)
		}
	}
	if err := validatePsiphonRouteStrategy(cfg); err != nil {
		return err
	}
	if err := validateRoutePolicyFields(cfg); err != nil {
		return err
	}
	return nil
}

func validatePsiphonRouteStrategy(cfg RoutingPluginConfig) error {
	strategy := normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "psiphon"}, cfg)
	if !allowedValue(strategy, "auto", "conduit_first", "conduit", "cdn_fronting", "direct") {
		return fmt.Errorf("%w: unsupported psiphon route_strategy %q", errPluginConfig, strategy)
	}
	if !allowedValue(normalizedConduitMode(cfg), "", "auto", "shirokhorshid", "public") {
		return fmt.Errorf("%w: unsupported psiphon conduit_mode %q", errPluginConfig, cfg.Fields["conduit_mode"])
	}
	if timeoutValue := strings.TrimSpace(cfg.Fields["conduit_timeout_seconds"]); timeoutValue != "" {
		timeoutSeconds, err := strconv.Atoi(timeoutValue)
		if err != nil || timeoutSeconds < 15 || timeoutSeconds > 1800 {
			return fmt.Errorf("%w: conduit_timeout_seconds must be between 15 and 1800", errPluginConfig)
		}
	}
	for _, key := range []string{"reject_censored_country_proxies", "conduit_fallback_to_public", "beast_mode", "share_proxy_on_lan"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !isBoolText(value) {
			return fmt.Errorf("%w: %s must be true or false", errPluginConfig, key)
		}
	}
	if strategy == "cdn_fronting" || normalizedFrontingPolicy(cfg) != "" {
		if strings.TrimSpace(cfg.Fields["fronting_ip_ref"]) == "" && strings.TrimSpace(cfg.Fields["cdn_fronting_ip_ref"]) == "" && strings.TrimSpace(cfg.Fields["fronting_sni"]) == "" && strings.TrimSpace(cfg.Fields["cdn_fronting_sni"]) == "" {
			return fmt.Errorf("%w: cdn_fronting route strategy requires a fronting_ip_ref or fronting_sni/cdn_fronting_sni", errPluginConfig)
		}
	}
	for _, key := range []string{"fronting_sni", "cdn_fronting_sni"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !isSafeHostnameLike(value) {
			return fmt.Errorf("%w: %s must be a hostname-like value", errPluginConfig, key)
		}
	}
	return nil
}

func validateWindscribeMode(cfg RoutingPluginConfig) error {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode == "" {
		mode = "external_vpn"
	}
	if !allowedValue(mode, "external_vpn", "local_proxy", "openvpn_udp", "openvpn_tcp", "tcp", "stealth", "wstunnel", "wireguard", "ikev2") {
		return fmt.Errorf("%w: unsupported windscribe mode %q", errPluginConfig, mode)
	}
	authMode := normalizedField(cfg, "auth_mode", "none")
	if !allowedValue(authMode, "none", "external_app", "profile_ref", "credential_ref", "auth_token_ref", "sso_external", "wsnet_session_ref", "wsnet_login_required") {
		return fmt.Errorf("%w: unsupported windscribe auth_mode %q", errPluginConfig, cfg.Fields["auth_mode"])
	}
	if authMode == "wsnet_login_required" {
		return fmt.Errorf("%w: windscribe wsnet login flow belongs to Android session ownership; use external_app/profile_ref/credential_ref/auth_token_ref/sso_external/wsnet_session_ref", errPluginConfig)
	}
	if authMode == "wsnet_session_ref" && strings.TrimSpace(cfg.CredentialRef) == "" {
		return fmt.Errorf("%w: windscribe wsnet_session_ref requires credential_ref containing a stored session handle", errPluginConfig)
	}
	if allowedValue(authMode, "auth_token_ref", "sso_external") && strings.TrimSpace(cfg.CredentialRef) == "" {
		return fmt.Errorf("%w: windscribe %s requires credential_ref", errPluginConfig, authMode)
	}
	if mode == "local_proxy" {
		if err := validateProxyEndpoint(cfg.Endpoint); err != nil {
			return err
		}
	}
	if allowedValue(mode, "openvpn_udp", "openvpn_tcp", "stealth", "wstunnel", "wireguard") && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: windscribe protocol mode requires profile_ref", errPluginConfig)
	}
	if allowedValue(mode, "tcp", "ikev2") && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: windscribe protocol mode requires profile_ref", errPluginConfig)
	}
	if strategy := normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "windscribe"}, cfg); !allowedValue(strategy, "provider_default", "direct", "profile_default") {
		return fmt.Errorf("%w: unsupported windscribe route_strategy %q", errPluginConfig, strategy)
	}
	return validateRoutePolicyFields(cfg)
}

func validateRoutePolicyFields(cfg RoutingPluginConfig) error {
	if !allowedValue(normalizedField(cfg, "dns_policy", "system_or_route_default"),
		"system_or_route_default", "remote_dns", "route_dns", "ctrld", "control_d", "robert", "doh", "dot", "custom_dns_ref", "no_dns") {
		return fmt.Errorf("%w: unsupported dns_policy %q", errPluginConfig, cfg.Fields["dns_policy"])
	}
	if !allowedValue(normalizedField(cfg, "split_tunnel", "scanner_app_only"),
		"scanner_app_only", "include_targets", "exclude_targets", "external_vpn_policy", "disabled") {
		return fmt.Errorf("%w: unsupported split_tunnel %q", errPluginConfig, cfg.Fields["split_tunnel"])
	}
	if !allowedValue(normalizedField(cfg, "upstream_mode", "none"),
		"none", "system_proxy", "proxy_ref", "direct", "provider_default") {
		return fmt.Errorf("%w: unsupported upstream_mode %q", errPluginConfig, cfg.Fields["upstream_mode"])
	}
	if !allowedValue(normalizedField(cfg, "downstream_mode", "scanner_to_route"),
		"scanner_to_route", "local_proxy_gateway", "vpn_interface", "provider_default") {
		return fmt.Errorf("%w: unsupported downstream_mode %q", errPluginConfig, cfg.Fields["downstream_mode"])
	}
	if !allowedValue(normalizedField(cfg, "proxy_gateway_scope", "loopback_only"),
		"loopback_only", "lan_shared") {
		return fmt.Errorf("%w: unsupported proxy_gateway_scope %q", errPluginConfig, cfg.Fields["proxy_gateway_scope"])
	}
	if normalizedField(cfg, "split_tunnel", "scanner_app_only") != "scanner_app_only" && strings.TrimSpace(cfg.ProfileRef) == "" {
		return fmt.Errorf("%w: split_tunnel policy requires profile_ref", errPluginConfig)
	}
	if normalizedField(cfg, "dns_policy", "system_or_route_default") == "custom_dns_ref" && strings.TrimSpace(cfg.Fields["dns_ref"]) == "" {
		return fmt.Errorf("%w: custom_dns_ref dns_policy requires dns_ref", errPluginConfig)
	}
	if normalizedField(cfg, "upstream_mode", "none") == "proxy_ref" && strings.TrimSpace(cfg.Fields["upstream_proxy_ref"]) == "" {
		return fmt.Errorf("%w: upstream proxy_ref requires upstream_proxy_ref", errPluginConfig)
	}
	if normalizedField(cfg, "proxy_gateway_scope", "loopback_only") == "lan_shared" && strings.TrimSpace(cfg.Fields["gateway_auth_ref"]) == "" {
		return fmt.Errorf("%w: lan_shared proxy gateway requires gateway_auth_ref", errPluginConfig)
	}
	if lanSharingEnabled(cfg) && normalizedField(cfg, "proxy_gateway_scope", "loopback_only") != "lan_shared" {
		return fmt.Errorf("%w: share_proxy_on_lan requires proxy_gateway_scope=lan_shared", errPluginConfig)
	}
	for _, key := range []string{"local_socks_port", "local_http_port", "lan_socks_port", "lan_http_port"} {
		if value := strings.TrimSpace(cfg.Fields[key]); value != "" && !validPort(value) {
			return fmt.Errorf("%w: %s must be a numeric TCP port", errPluginConfig, key)
		}
	}
	chain := normalizedProviderChain(cfg)
	if !allowedValue(chain, "none", "psiphon_over_windscribe", "windscribe_over_psiphon", "generic_proxy_over_windscribe", "windscribe_over_generic_proxy") {
		return fmt.Errorf("%w: unsupported provider_chain %q", errPluginConfig, cfg.Fields["provider_chain"])
	}
	if chain != "none" && strings.TrimSpace(cfg.Fields["chain_upstream_ref"]) == "" {
		return fmt.Errorf("%w: provider_chain requires chain_upstream_ref", errPluginConfig)
	}
	return nil
}

func readinessProbeForPlugin(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	switch plugin.PluginType {
	case "psiphon":
		mode := normalizedProtocolMode(plugin, cfg)
		if mode == "external_vpn_apk" || mode == "external_vpn" {
			return "verify user-connected Psiphon APK/VPN route by external IP, DNS path, and route observation; do not drive private APK UI"
		}
		return "check tunnel-core/library state, parse diagnostic notices such as ListeningSocksProxyPort/ListeningHttpProxyPort, and probe local SOCKS/HTTP proxy on loopback"
	case "windscribe":
		mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
		if mode == "" {
			mode = "external_vpn"
		}
		if mode == "local_proxy" {
			return "probe user-supplied Windscribe-routed local SOCKS/HTTP proxy endpoint"
		}
		if normalizedAuthMode(plugin, cfg) == "wsnet_session_ref" {
			return "validate stored wsnet session handle, fetch session/server/profile metadata through wsnet adapter, then verify route observation"
		}
		return "verify external VPN/profile route via user-selected profile reference and route observation"
	case "generic_proxy":
		return "probe configured SOCKS/HTTP proxy endpoint before attaching route"
	default:
		return "plugin-specific readiness probe required"
	}
}

func pluginCapabilities(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) []string {
	switch plugin.PluginType {
	case "psiphon":
		caps := []string{
			"tunnel_core_supervision",
			"external_vpn_apk_labeling",
			"local_socks_http_proxy_readiness",
			"diagnostic_notice_parsing",
			"conduit_route_strategy",
			"cdn_fronting_route_strategy",
			"beast_establishment_intensity",
			"conduit_public_fallback_policy",
			"lan_proxy_sharing_policy",
			"upstream_proxy_policy",
			"remote_dns_when_route_attached",
		}
		if normalizedProviderChain(cfg) != "none" {
			caps = append(caps, "provider_route_chaining")
		}
		return caps
	case "windscribe":
		return []string{
			"external_vpn_route_labeling",
			"local_proxy_gateway",
			"openvpn_udp",
			"openvpn_tcp",
			"tcp_mode_alias",
			"stealth_stunnel",
			"wstunnel",
			"wireguard",
			"ikev2_external_profile",
			"dns_policy",
			"ctrld_policy",
			"robert_dns_filter_policy",
			"split_tunnel_policy",
			"upstream_downstream_route_observation",
			"provider_route_chaining",
			"lan_proxy_gateway_metadata",
			"custom_openvpn_wireguard_profile_refs",
			"optional_auth_token_or_sso_reference",
			"optional_wsnet_session_ref_auth_boundary",
			"interactive_login_flow_planned_not_raw_http",
		}
	case "generic_proxy":
		return []string{"socks5", "http_connect", "remote_dns_when_route_attached", "credential_ref_only"}
	default:
		return nil
	}
}

func routeBindingForPlugin(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	switch plugin.PluginType {
	case "psiphon":
		mode := normalizedProtocolMode(plugin, cfg)
		if mode == "external_vpn_apk" || mode == "external_vpn" {
			return "external_vpn_observation"
		}
		return "tunnel_core_local_proxy"
	case "windscribe":
		switch normalizedProtocolMode(plugin, cfg) {
		case "local_proxy":
			return "local_proxy_gateway"
		case "openvpn_udp", "openvpn_tcp", "stealth", "wstunnel", "wireguard", "ikev2":
			return "profile_backed_vpn_or_proxy"
		default:
			return "external_vpn_observation"
		}
	case "generic_proxy":
		return "generic_local_proxy"
	default:
		return "custom_route"
	}
}

func providerComponents(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) []string {
	switch plugin.PluginType {
	case "psiphon":
		mode := normalizedProtocolMode(plugin, cfg)
		if mode == "external_vpn_apk" || mode == "external_vpn" {
			return []string{"external_psiphon_app", "android_vpn_observer", "route_observer"}
		}
		components := []string{"psiphon_tunnel_core", "config_ref_store", "process_supervisor", "diagnostic_notice_parser", "local_proxy_probe", "route_manager"}
		switch normalizedRouteStrategy(plugin, cfg) {
		case "conduit", "conduit_first":
			components = append(components, "conduit_selector", "conduit_fallback_timer")
		case "cdn_fronting":
			components = append(components, "cdn_fronting_policy")
		}
		if beastModeEnabled(cfg) {
			components = append(components, "aggressive_establishment_policy")
		}
		if lanSharingEnabled(cfg) {
			components = append(components, "lan_proxy_gateway_policy")
		}
		if normalizedProviderChain(cfg) != "none" {
			components = append(components, "provider_chain_supervisor")
		}
		return components
	case "windscribe":
		mode := normalizedProtocolMode(plugin, cfg)
		components := []string{"edge_route_manager", "route_observer", "redaction_filter"}
		switch mode {
		case "local_proxy":
			components = append(components, "local_proxy_probe", "proxy_gateway_policy")
		case "openvpn_udp", "openvpn_tcp":
			components = append(components, "openvpn_profile_ref", "protocol_profile_validator")
		case "stealth":
			components = append(components, "openvpn_tcp_profile_ref", "stunnel_profile_metadata")
		case "wstunnel":
			components = append(components, "openvpn_profile_ref", "websocket_tunnel_profile_metadata")
		case "wireguard":
			components = append(components, "wireguard_profile_ref", "wireguard_secret_guard")
		case "ikev2":
			components = append(components, "ikev2_profile_ref", "platform_vpn_capability_check")
		default:
			components = append(components, "external_vpn_observer")
		}
		if normalizedAuthMode(plugin, cfg) == "wsnet_session_ref" {
			components = append(components, "wsnet_session_ref_adapter")
		}
		switch normalizedField(cfg, "dns_policy", "system_or_route_default") {
		case "ctrld", "control_d":
			components = append(components, "ctrld_dns_policy")
		case "robert":
			components = append(components, "robert_filter_policy")
		case "doh", "dot", "custom_dns_ref":
			components = append(components, "custom_dns_policy")
		}
		if normalizedField(cfg, "split_tunnel", "scanner_app_only") != "scanner_app_only" {
			components = append(components, "split_tunnel_policy")
		}
		if normalizedProviderChain(cfg) != "none" {
			components = append(components, "provider_chain_supervisor")
		}
		if lanSharingEnabled(cfg) {
			components = append(components, "lan_proxy_gateway_policy")
		}
		return components
	case "generic_proxy":
		return []string{"generic_proxy_parser", "local_proxy_probe", "route_manager"}
	default:
		return nil
	}
}

func routeObservations(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) []string {
	base := []string{"route_id", "route_binding", "network_path", "dns_policy", "remote_dns", "readiness_probe", "latency_ms", "last_error_code"}
	switch plugin.PluginType {
	case "psiphon":
		return append(base, "route_strategy", "conduit_mode", "fronting_policy", "beast_mode", "provider_chain", "lan_sharing", "tunnel_core_pid", "listening_socks_port", "listening_http_proxy_port", "diagnostic_notice_state", "external_ip_delta")
	case "windscribe":
		return append(base, "protocol_mode", "auth_mode", "split_tunnel", "upstream_mode", "downstream_mode", "proxy_gateway_scope", "provider_chain", "lan_sharing", "external_ip_delta", "dns_resolver_delta")
	case "generic_proxy":
		return append(base, "proxy_protocol", "proxy_connect_status")
	default:
		return base
	}
}

func routeObservationPreview(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) RouteObservationPreview {
	providerID := plugin.PluginType
	if plugin.PluginType == "generic_proxy" {
		providerID = ""
	}
	routeBinding := routeBindingForPlugin(plugin, cfg)
	protocolMode := normalizedProtocolMode(plugin, cfg)
	authMode := normalizedAuthMode(plugin, cfg)
	dnsPolicy := normalizedField(cfg, "dns_policy", "system_or_route_default")
	splitTunnel := normalizedField(cfg, "split_tunnel", "scanner_app_only")
	upstreamMode := normalizedField(cfg, "upstream_mode", "none")
	downstreamMode := normalizedField(cfg, "downstream_mode", "scanner_to_route")
	proxyGatewayMode := normalizedField(cfg, "proxy_gateway_scope", "loopback_only")
	routeStrategy := normalizedRouteStrategy(plugin, cfg)
	conduitMode := normalizedConduitMode(cfg)
	providerChain := normalizedProviderChain(cfg)
	frontingPolicy := normalizedFrontingPolicy(cfg)
	lanSharing := lanSharingEnabled(cfg)
	beastMode := beastModeEnabled(cfg)
	networkPath := "plugin:" + plugin.PluginID + ":" + protocolMode
	if plugin.PluginType == "generic_proxy" {
		networkPath = "proxy:generic:" + protocolMode
	}
	evidence := map[string]any{
		"validation_dry_run_only": true,
		"route_attachable":        false,
		"readiness_probe":         readinessProbeForPlugin(plugin, cfg),
		"components":              providerComponents(plugin, cfg),
		"required_observations":   routeObservations(plugin, cfg),
		"route_strategy":          routeStrategy,
		"provider_chain":          providerChain,
		"lan_sharing":             lanSharing,
	}
	if conduitMode != "" {
		evidence["conduit_mode"] = conduitMode
	}
	if frontingPolicy != "" {
		evidence["fronting_policy"] = frontingPolicy
	}
	if beastMode {
		evidence["establishment_intensity"] = "beast"
	}
	if cfg.Endpoint != "" {
		evidence["endpoint_present"] = true
	}
	if cfg.ConfigRef != "" {
		evidence["config_ref_present"] = true
	}
	if cfg.ProfileRef != "" {
		evidence["profile_ref_present"] = true
	}
	if cfg.CredentialRef != "" {
		evidence["credential_ref_present"] = true
	}
	if plugin.PluginType == "psiphon" && (protocolMode == "tunnel_core_supervised" || protocolMode == "tunnel_core_library") {
		evidence["required_readiness_state"] = "proxy_listening"
		evidence["required_notice_fields"] = []string{"ListeningSocksProxyPort", "ListeningHttpProxyPort"}
		evidence["shirokhorshid_config_model"] = []string{"protocolSelection", "cdnFrontingCustomIpList", "cdnFrontingCustomSni", "beastMode", "conduitMode", "shareProxyOnNetwork"}
	}
	if plugin.PluginType == "windscribe" {
		evidence["upstream_downstream_model"] = true
		evidence["dns_resolver_delta_required"] = dnsPolicy != "no_dns"
	}
	routeNotReady := "PLUGIN_ROUTE_NOT_READY"
	return RouteObservationPreview{
		SchemaVersion:      1,
		ObservationID:      "preview:" + cfg.RouteID,
		RouteID:            cfg.RouteID,
		RouteType:          plugin.RouteType,
		RouteBinding:       routeBinding,
		NetworkPath:        networkPath,
		ProviderID:         nullableString(providerID),
		ProtocolMode:       nullableString(protocolMode),
		AuthMode:           nullableString(authMode),
		DNSPolicy:          dnsPolicy,
		RemoteDNSRequested: cfg.RemoteDNS,
		RemoteDNSObserved:  nil,
		SplitTunnel:        nullableString(splitTunnel),
		UpstreamMode:       nullableString(upstreamMode),
		DownstreamMode:     nullableString(downstreamMode),
		ProxyGatewayMode:   nullableString(proxyGatewayMode),
		RouteStrategy:      nullableString(routeStrategy),
		ConduitMode:        nullableString(conduitMode),
		ProviderChain:      nullableString(providerChain),
		FrontingPolicy:     nullableString(frontingPolicy),
		LANSharing:         lanSharing,
		BeastMode:          beastMode,
		ReadinessState:     "not_checked",
		Status:             "skipped",
		LatencyMS:          0,
		ErrorCode:          &routeNotReady,
		Evidence:           evidence,
	}
}

func validateRouteObservationTemplate(observation RouteObservationPreview) error {
	if observation.SchemaVersion != 1 {
		return fmt.Errorf("%w: route observation template schema_version must be 1", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.ObservationID) == "" || strings.TrimSpace(observation.RouteID) == "" {
		return fmt.Errorf("%w: route observation template must include observation_id and route_id", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.RouteType) == "" || strings.TrimSpace(observation.RouteBinding) == "" || strings.TrimSpace(observation.NetworkPath) == "" {
		return fmt.Errorf("%w: route observation template must include route type/binding/path", errPluginDescriptor)
	}
	if strings.TrimSpace(observation.DNSPolicy) == "" {
		return fmt.Errorf("%w: route observation template must include dns_policy", errPluginDescriptor)
	}
	if observation.ReadinessState != "not_checked" {
		return fmt.Errorf("%w: route observation template readiness_state must be not_checked", errPluginDescriptor)
	}
	if observation.Status != "skipped" {
		return fmt.Errorf("%w: route observation template status must be skipped", errPluginDescriptor)
	}
	if observation.ErrorCode == nil || *observation.ErrorCode != "PLUGIN_ROUTE_NOT_READY" {
		return fmt.Errorf("%w: route observation template error_code must be PLUGIN_ROUTE_NOT_READY", errPluginDescriptor)
	}
	if observation.Evidence == nil {
		return fmt.Errorf("%w: route observation template evidence is required", errPluginDescriptor)
	}
	dryRun, ok := observation.Evidence["validation_dry_run_only"].(bool)
	if !ok || !dryRun {
		return fmt.Errorf("%w: route observation template must set validation_dry_run_only=true", errPluginDescriptor)
	}
	attachable, ok := observation.Evidence["route_attachable"].(bool)
	if !ok || attachable {
		return fmt.Errorf("%w: route observation template must set route_attachable=false", errPluginDescriptor)
	}
	probe, ok := observation.Evidence["readiness_probe"].(string)
	if !ok || strings.TrimSpace(probe) == "" {
		return fmt.Errorf("%w: route observation template must include readiness_probe", errPluginDescriptor)
	}
	components, ok := observation.Evidence["components"].([]string)
	if !ok || len(components) == 0 {
		componentsAny, okAny := observation.Evidence["components"].([]any)
		if !okAny || len(componentsAny) == 0 {
			return fmt.Errorf("%w: route observation template must include components", errPluginDescriptor)
		}
	}
	observations, ok := observation.Evidence["required_observations"].([]string)
	if !ok || len(observations) == 0 {
		obsAny, okAny := observation.Evidence["required_observations"].([]any)
		if !okAny || len(obsAny) == 0 {
			return fmt.Errorf("%w: route observation template must include required_observations", errPluginDescriptor)
		}
	}
	return nil
}

func nullableString(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func normalizedAuthMode(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	mode := normalizedField(cfg, "auth_mode", "")
	if mode != "" {
		return mode
	}
	switch plugin.PluginType {
	case "windscribe":
		return "none"
	case "psiphon":
		return "config_ref"
	default:
		return "credential_ref"
	}
}

func normalizedProtocolMode(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	mode := strings.TrimSpace(strings.ToLower(cfg.Fields["mode"]))
	if mode != "" {
		if plugin.PluginType == "windscribe" && mode == "tcp" {
			return "openvpn_tcp"
		}
		return mode
	}
	switch plugin.PluginType {
	case "psiphon":
		return "tunnel_core_supervised"
	case "windscribe":
		return "external_vpn"
	default:
		return plugin.RouteType
	}
}

func normalizedRouteStrategy(plugin RoutingPluginDescriptor, cfg RoutingPluginConfig) string {
	strategy := normalizedField(cfg, "route_strategy", "")
	if strategy == "" && plugin.PluginType == "psiphon" {
		strategy = normalizedField(cfg, "protocol_selection", "")
	}
	if strategy != "" {
		return strategy
	}
	switch plugin.PluginType {
	case "psiphon":
		return "auto"
	case "windscribe":
		return "provider_default"
	default:
		return "direct"
	}
}

func normalizedConduitMode(cfg RoutingPluginConfig) string {
	return normalizedField(cfg, "conduit_mode", "")
}

func normalizedProviderChain(cfg RoutingPluginConfig) string {
	return normalizedField(cfg, "provider_chain", "none")
}

func normalizedFrontingPolicy(cfg RoutingPluginConfig) string {
	if normalizedRouteStrategy(RoutingPluginDescriptor{PluginType: "psiphon"}, cfg) == "cdn_fronting" {
		return "cdn_fronting"
	}
	if strings.TrimSpace(cfg.Fields["fronting_ip_ref"]) != "" || strings.TrimSpace(cfg.Fields["cdn_fronting_ip_ref"]) != "" ||
		strings.TrimSpace(cfg.Fields["fronting_sni"]) != "" || strings.TrimSpace(cfg.Fields["cdn_fronting_sni"]) != "" {
		return "custom_cdn_fronting"
	}
	return ""
}

func lanSharingEnabled(cfg RoutingPluginConfig) bool {
	return normalizedField(cfg, "share_proxy_on_lan", "false") == "true" || normalizedField(cfg, "proxy_gateway_scope", "loopback_only") == "lan_shared"
}

func beastModeEnabled(cfg RoutingPluginConfig) bool {
	return normalizedField(cfg, "beast_mode", "false") == "true" || normalizedField(cfg, "establishment_intensity", "normal") == "beast"
}

func normalizedField(cfg RoutingPluginConfig, key, fallback string) string {
	if cfg.Fields == nil {
		return fallback
	}
	value := strings.TrimSpace(strings.ToLower(cfg.Fields[key]))
	if value == "" {
		return fallback
	}
	return value
}

func isBoolText(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "true" || value == "false"
}

func isSafeHostnameLike(value string) bool {
	if len(value) > 253 || containsCRLF(value) {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '*' {
			continue
		}
		return false
	}
	return strings.Contains(value, ".") && !strings.Contains(value, "..")
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func routingPluginsJSON() ([]byte, error) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string]any{
		"schema_version": 1,
		"plugins":        registry.List(),
	}, "", "  ")
}
