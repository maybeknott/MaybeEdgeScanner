package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultRoutingPluginRegistryContainsExpectedAdapters(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"generic-proxy", "psiphon", "windscribe"} {
		if _, ok := registry.Get(id); !ok {
			t.Fatalf("missing plugin %s", id)
		}
	}
}

func TestRoutingPluginValidationRejectsSecretsPolicyDrift(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-psiphon",
		PluginType:        "psiphon",
		DisplayName:       "Bad Psiphon",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "plugin",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "authenticated_http",
		LocalAPIRequired:  true,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      false,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected psiphon secret policy validation error")
	}
}

func TestRoutingPluginValidationRejectsUnsupportedEnums(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-route",
		PluginType:        "generic_proxy",
		DisplayName:       "Bad Route",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "raw_packet",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "none",
		LocalAPIRequired:  false,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected unsupported route_type validation error")
	}
}

func TestRoutingPluginValidationRejectsImpossibleLocalAPIContract(t *testing.T) {
	descriptor := RoutingPluginDescriptor{
		SchemaVersion:     1,
		PluginID:          "bad-api",
		PluginType:        "generic_proxy",
		DisplayName:       "Bad API",
		Version:           "v1",
		SourceURL:         "https://example.test",
		License:           "test",
		RouteType:         "socks5",
		CredentialMode:    "user_supplied",
		LocalAPIMode:      "none",
		LocalAPIRequired:  true,
		SecretPolicy:      "credential_ref_only",
		Enabled:           false,
		EnabledByDefault:  false,
		SupportsIPv4:      true,
		SupportsIPv6:      true,
		SupportsRemoteDNS: true,
		DiagnosticLabel:   "bad",
	}
	if err := validateRoutingPluginDescriptor(descriptor); err == nil {
		t.Fatal("expected impossible local API contract validation error")
	}
}

func TestRoutingPluginRedactsKnownAndGenericSecrets(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	plugin, _ := registry.Get("windscribe")
	out := redactPluginDiagnostics(plugin, map[string]string{
		"username":              "alice",
		"wireguard_private_key": "secret-key",
		"api_token":             "token",
		"public_endpoint":       "example.test:443",
	})
	if out["username"] != "[REDACTED]" || out["wireguard_private_key"] != "[REDACTED]" || out["api_token"] != "[REDACTED]" {
		t.Fatalf("secrets not redacted: %#v", out)
	}
	if out["public_endpoint"] != "example.test:443" {
		t.Fatalf("non-secret field redacted incorrectly: %#v", out)
	}
}

func TestRoutingPluginsJSONDoesNotLeakPlaceholderSecrets(t *testing.T) {
	body, err := routingPluginsJSON()
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{"clientsecret", "password=", "api_token="} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("plugin JSON leaked forbidden token %q: %s", forbidden, string(body))
		}
	}
}

func TestRoutingPluginsEndpointIsReadOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/plugins", nil)
	routingPlugins(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if !strings.Contains(rec.Body.String(), `"error_code":"METHOD_NOT_ALLOWED"`) || !strings.Contains(rec.Body.String(), `"required_method":"GET"`) {
		t.Fatalf("expected structured method error, got %s", rec.Body.String())
	}
}

func TestRoutingPluginConfigAcceptsPsiphonConfigReference(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-core",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		LocalAPIURL:   "http://127.0.0.1:28080",
		ConfigRef:     "ref:psiphon-admin-config",
		Fields: map[string]string{
			"client_secret": "ref:secret",
			"region":        "auto",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.RedactedConfig["client_secret"] != "[REDACTED]" {
		t.Fatalf("unexpected validation result: %#v", result)
	}
	if !result.DryRunOnly || result.Attachable {
		t.Fatalf("plugin route validation must remain dry-run until scan route attachment exists: %#v", result)
	}
	if result.ReadinessProbe == "" {
		t.Fatalf("missing readiness probe: %#v", result)
	}
	if result.RouteBinding != "tunnel_core_local_proxy" {
		t.Fatalf("psiphon route binding not reflected: %#v", result)
	}
	if !containsString(result.Components, "diagnostic_notice_parser") || !containsString(result.Observations, "listening_socks_port") {
		t.Fatalf("psiphon components/observations missing: %#v", result)
	}
	if result.Observation.RouteBinding != "tunnel_core_local_proxy" ||
		result.Observation.ProtocolMode == nil ||
		*result.Observation.ProtocolMode != "tunnel_core_supervised" ||
		result.Observation.ErrorCode == nil ||
		*result.Observation.ErrorCode != "PLUGIN_ROUTE_NOT_READY" {
		t.Fatalf("psiphon observation template missing readiness boundary: %#v", result.Observation)
	}
}

func TestRoutingPluginConfigAcceptsPsiphonConduitFrontingBeastAndLanShare(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-conduit",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		ConfigRef:     "ref:psiphon-config",
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields: map[string]string{
			"mode":                            "tunnel_core_supervised",
			"route_strategy":                  "cdn_fronting",
			"conduit_mode":                    "shirokhorshid",
			"conduit_timeout_seconds":         "180",
			"reject_censored_country_proxies": "true",
			"cdn_fronting_ip_ref":             "ref:fronting-ips",
			"cdn_fronting_sni":                "front.example.test",
			"beast_mode":                      "true",
			"proxy_gateway_scope":             "lan_shared",
			"share_proxy_on_lan":              "true",
			"gateway_auth_ref":                "ref:lan-auth",
			"lan_socks_port":                  "1080",
			"lan_http_port":                   "8080",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RouteStrategy != "cdn_fronting" || result.ConduitMode != "shirokhorshid" || result.FrontingPolicy != "cdn_fronting" {
		t.Fatalf("fronting strategy not reflected: %#v", result)
	}
	if !result.LANSharing || !result.BeastMode {
		t.Fatalf("lan/beast policy not reflected: %#v", result)
	}
	if !result.Attachable {
		t.Fatalf("psiphon supervised mode with validated local proxy endpoint must be attachable: %#v", result)
	}
	psiphonAttachable, ok := result.Observation.Evidence["route_attachable"].(bool)
	if !ok || !psiphonAttachable {
		t.Fatalf("expected route_attachable=true for psiphon local proxy route, got %#v", result.Observation.Evidence["route_attachable"])
	}
	if result.Observation.RouteStrategy == nil || *result.Observation.RouteStrategy != "cdn_fronting" ||
		result.Observation.FrontingPolicy == nil || *result.Observation.FrontingPolicy != "cdn_fronting" ||
		!result.Observation.LANSharing || !result.Observation.BeastMode {
		t.Fatalf("observation template missing psiphon route policy: %#v", result.Observation)
	}
}

func TestRoutingPluginConfigMarksGenericProxyAttachable(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-generic-attachable",
		PluginID:      "generic-proxy",
		Enabled:       true,
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields:        map[string]string{"dns_policy": "remote"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || !result.DryRunOnly || !result.Attachable {
		t.Fatalf("expected dry-run + attachable generic proxy validation, got %#v", result)
	}
	attachable, ok := result.Observation.Evidence["route_attachable"].(bool)
	if !ok || !attachable {
		t.Fatalf("expected route_attachable=true for generic proxy observation evidence, got %#v", result.Observation.Evidence["route_attachable"])
	}
}

func TestRoutingPluginConfigRejectsUnsupportedProviderField(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-unknown-field",
		PluginID:      "psiphon",
		Enabled:       true,
		ConfigRef:     "ref:psiphon-config",
		Fields: map[string]string{
			"made_up_knob": "true",
		},
	})
	if err == nil {
		t.Fatal("expected unsupported provider field rejection")
	}
}

func TestRoutingPluginConfigAcceptsProviderChainReference(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-over-psiphon",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-wireguard",
		CredentialRef: "ref:windscribe-session",
		Fields: map[string]string{
			"mode":               "wireguard",
			"auth_mode":          "wsnet_session_ref",
			"provider_chain":     "windscribe_over_psiphon",
			"chain_upstream_ref": "ref:route-psiphon",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderChain != "windscribe_over_psiphon" || result.Observation.ProviderChain == nil || *result.Observation.ProviderChain != "windscribe_over_psiphon" {
		t.Fatalf("provider chain not reflected: %#v", result)
	}
}

func TestRoutingPluginConfigRejectsProviderChainWithoutRef(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-chain-missing-ref",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-wireguard",
		Fields: map[string]string{
			"mode":           "wireguard",
			"provider_chain": "windscribe_over_psiphon",
		},
	})
	if err == nil {
		t.Fatal("expected provider chain ref rejection")
	}
}

func TestRoutingPluginConfigRejectsInlineWindscribeSecret(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe",
		PluginID:      "windscribe",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:profile",
		Fields: map[string]string{
			"wireguard_private_key": "actual-private-key",
		},
	})
	if err == nil {
		t.Fatal("expected inline secret rejection")
	}
}

func TestRoutingPluginConfigRejectsUnsafeProviderFields(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	cases := []map[string]string{
		{"mode": "wireguard\r\nInjected: true"},
		{"bad key": "wireguard"},
		{"": "wireguard"},
	}
	for _, fields := range cases {
		_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "route-windscribe",
			PluginID:      "windscribe",
			Enabled:       true,
			ProfileRef:    "ref:profile",
			Fields:        fields,
		})
		if err == nil {
			t.Fatalf("expected unsafe field rejection for %#v", fields)
		}
	}
}

func TestRouteObservationPreviewKeepsSchemaShape(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-preview",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:profile",
		Fields:        map[string]string{"mode": "wireguard"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result.Observation)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{"schema_version", "observation_id", "route_id", "route_type", "route_binding", "network_path", "provider_id", "protocol_mode", "auth_mode", "dns_policy", "remote_dns_requested", "remote_dns_observed", "split_tunnel", "upstream_mode", "downstream_mode", "proxy_gateway_mode", "readiness_state", "status", "latency_ms", "error_code", "evidence"}
	for _, field := range required {
		if !strings.Contains(string(encoded), `"`+field+`"`) {
			t.Fatalf("observation template missing %s: %s", field, string(encoded))
		}
	}
	if !strings.Contains(string(encoded), `"PLUGIN_ROUTE_NOT_READY"`) {
		t.Fatalf("observation template missing readiness error code: %s", string(encoded))
	}
}

func TestRouteObservationTemplateValidationRejectsNonDryRunEvidence(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	plugin, ok := registry.Get("windscribe")
	if !ok {
		t.Fatal("missing windscribe plugin")
	}
	preview := routeObservationPreview(plugin, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-preview-invalid",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:profile",
		Fields:        map[string]string{"mode": "wireguard"},
	})
	preview.Evidence["validation_dry_run_only"] = false
	if err := validateRouteObservationTemplate(preview); err == nil {
		t.Fatal("expected route observation template dry-run validation failure")
	}
}

func TestRouteObservationTemplateValidationRejectsMissingRequiredObservations(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	plugin, ok := registry.Get("psiphon")
	if !ok {
		t.Fatal("missing psiphon plugin")
	}
	preview := routeObservationPreview(plugin, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-preview-invalid",
		PluginID:      "psiphon",
		Enabled:       true,
		ConfigRef:     "ref:psiphon-config",
		Fields: map[string]string{
			"mode": "tunnel_core_supervised",
		},
	})
	delete(preview.Evidence, "required_observations")
	if err := validateRouteObservationTemplate(preview); err == nil {
		t.Fatal("expected route observation template required_observations validation failure")
	}
}

func TestRoutingPluginConfigRejectsEndpointUserInfo(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-proxy",
		PluginID:      "generic-proxy",
		Enabled:       true,
		RemoteDNS:     true,
		Endpoint:      "socks5://user:pass@127.0.0.1:1080",
		CredentialRef: "ref:proxy-creds",
	})
	if err == nil {
		t.Fatal("expected endpoint userinfo rejection")
	}
}

func TestRoutingPluginConfigRejectsLocalAPIParserBypasses(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, localAPIURL := range []string{
		"http://127.0.0.1:80@evil.test",
		"http://localhost:abc",
		"http://192.0.2.10:28080",
		"http://127.0.0.1:28080?token=secret",
		"https://127.0.0.1:28080",
	} {
		_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "route-psiphon-core",
			PluginID:      "psiphon",
			Enabled:       true,
			RemoteDNS:     true,
			LocalAPIURL:   localAPIURL,
			ConfigRef:     "ref:psiphon-admin-config",
		})
		if err == nil {
			t.Fatalf("expected local_api_url rejection for %q", localAPIURL)
		}
	}
}

func TestRoutingPluginConfigRejectsMalformedGenericProxyEndpoint(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"http://127.0.0.1:notaport",
		"socks5://127.0.0.1",
		"https://127.0.0.1:1080",
		"socks5://127.0.0.1:1080/path",
	} {
		_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "route-proxy",
			PluginID:      "generic-proxy",
			Enabled:       true,
			Endpoint:      endpoint,
			CredentialRef: "ref:proxy-creds",
		})
		if err == nil {
			t.Fatalf("expected endpoint rejection for %q", endpoint)
		}
	}
}

func TestRoutingPluginConfigAcceptsWindscribeProtocolModes(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"openvpn_udp", "openvpn_tcp", "tcp", "stealth", "wstunnel", "wireguard", "ikev2"} {
		result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
			SchemaVersion: 1,
			RouteID:       "route-windscribe-" + mode,
			PluginID:      "windscribe",
			Enabled:       true,
			RemoteDNS:     true,
			ProfileRef:    "ref:windscribe-profile-" + mode,
			Fields: map[string]string{
				"mode": mode,
			},
		})
		if err != nil {
			t.Fatalf("mode %s rejected: %v", mode, err)
		}
		if !result.DryRunOnly || result.Attachable || result.ReadinessProbe == "" {
			t.Fatalf("unexpected validation result for mode %s: %#v", mode, result)
		}
		if mode == "tcp" && result.ProtocolMode != "openvpn_tcp" {
			t.Fatalf("tcp alias not normalized: %#v", result)
		}
	}
}

func TestRoutingPluginConfigAcceptsWindscribeLocalProxyMode(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-local-proxy",
		PluginID:      "windscribe",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:windscribe-local-proxy",
		Endpoint:      "socks5://127.0.0.1:1080",
		Fields: map[string]string{
			"mode": "local_proxy",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ReadinessProbe == "" {
		t.Fatalf("missing readiness probe: %#v", result)
	}
	if !result.Attachable {
		t.Fatalf("windscribe local proxy mode must be attachable when endpoint is validated: %#v", result)
	}
	windscribeAttachable, ok := result.Observation.Evidence["route_attachable"].(bool)
	if !ok || !windscribeAttachable {
		t.Fatalf("expected route_attachable=true for windscribe local proxy mode, got %#v", result.Observation.Evidence["route_attachable"])
	}
	if result.RouteBinding != "local_proxy_gateway" || !containsString(result.Components, "proxy_gateway_policy") {
		t.Fatalf("local proxy binding/components missing: %#v", result)
	}
	if result.Observation.RouteBinding != "local_proxy_gateway" || result.Observation.ProviderID == nil || *result.Observation.ProviderID != "windscribe" {
		t.Fatalf("local proxy observation template missing provider route evidence: %#v", result.Observation)
	}
}

func TestRoutingPluginConfigAcceptsWindscribeRoutePolicies(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-policy",
		PluginID:      "windscribe",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:windscribe-policy",
		Endpoint:      "http://127.0.0.1:8080",
		Fields: map[string]string{
			"mode":                "local_proxy",
			"dns_policy":          "ctrld",
			"split_tunnel":        "include_targets",
			"upstream_mode":       "proxy_ref",
			"upstream_proxy_ref":  "ref:upstream-proxy",
			"downstream_mode":     "local_proxy_gateway",
			"proxy_gateway_scope": "lan_shared",
			"gateway_auth_ref":    "ref:gateway-auth",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DNSPolicy != "ctrld" || result.SplitTunnel != "include_targets" || result.UpstreamMode != "proxy_ref" || result.DownstreamMode != "local_proxy_gateway" {
		t.Fatalf("policy fields not reflected: %#v", result)
	}
	if !containsString(result.Components, "ctrld_dns_policy") || !containsString(result.Components, "split_tunnel_policy") || !containsString(result.Observations, "proxy_gateway_scope") {
		t.Fatalf("policy components/observations missing: %#v", result)
	}
}

func TestRoutingPluginConfigRejectsWindscribeUnimplementedLogin(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-login",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-login",
		Fields: map[string]string{
			"auth_mode": "wsnet_login_required",
		},
	})
	if err == nil {
		t.Fatal("expected unimplemented wsnet login mode rejection")
	}
}

func TestRoutingPluginConfigRejectsSharedWindscribeGatewayWithoutAuth(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-shared-gateway",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-profile",
		Endpoint:      "http://127.0.0.1:8080",
		Fields: map[string]string{
			"mode":                "local_proxy",
			"proxy_gateway_scope": "lan_shared",
		},
	})
	if err == nil {
		t.Fatal("expected lan_shared gateway without gateway_auth_ref rejection")
	}
}

func TestRoutingPluginConfigAcceptsWindscribeSessionReference(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-session",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-session-profile",
		CredentialRef: "ref:windscribe-wsnet-session",
		Fields: map[string]string{
			"auth_mode": "wsnet_session_ref",
			"mode":      "wireguard",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AuthMode != "wsnet_session_ref" {
		t.Fatalf("auth mode not reflected: %#v", result)
	}
	if !containsString(result.Components, "wsnet_session_ref_adapter") {
		t.Fatalf("wsnet component missing: %#v", result)
	}
}

func TestRoutingPluginConfigAcceptsWindscribeAuthTokenReferenceAndRobertPolicy(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-auth-token",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-profile",
		CredentialRef: "ref:windscribe-auth-token",
		Fields: map[string]string{
			"auth_mode":  "auth_token_ref",
			"mode":       "openvpn_tcp",
			"dns_policy": "robert",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.AuthMode != "auth_token_ref" || result.DNSPolicy != "robert" || !containsString(result.Components, "robert_filter_policy") {
		t.Fatalf("auth token or robert policy not reflected: %#v", result)
	}
	if result.Observation.AuthMode == nil ||
		*result.Observation.AuthMode != "auth_token_ref" ||
		result.Observation.DNSPolicy != "robert" ||
		result.Observation.Evidence["dns_resolver_delta_required"] != true {
		t.Fatalf("auth token observation template not reflected: %#v", result.Observation)
	}
}

func TestRoutingPluginConfigAcceptsPsiphonExternalAPKMode(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-psiphon-apk",
		PluginID:      "psiphon",
		Enabled:       true,
		RemoteDNS:     true,
		ProfileRef:    "ref:user-connected-psiphon-apk",
		Fields: map[string]string{
			"mode":         "external_vpn_apk",
			"package_name": "com.psiphon3",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ProtocolMode != "external_vpn_apk" || result.ReadinessProbe == "" {
		t.Fatalf("unexpected external APK result: %#v", result)
	}
	if result.RouteBinding != "external_vpn_observation" || !containsString(result.Components, "external_psiphon_app") {
		t.Fatalf("external APK binding/components missing: %#v", result)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
