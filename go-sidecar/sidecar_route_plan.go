package main

import (
	"net/url"
	"strings"
	"time"
)

type scanRoutePlan struct {
	Valid      bool                          `json:"valid"`
	Validation RoutingPluginConfigValidation `json:"validation,omitempty"`
	RuntimeCfg *RouteConfig                  `json:"-"`
}

func validateScanRoutePlugin(cfg *RoutingPluginConfig) (scanRoutePlan, error) {
	if cfg == nil || strings.TrimSpace(cfg.PluginID) == "" {
		return scanRoutePlan{}, nil
	}
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		return scanRoutePlan{}, err
	}
	validation, err := validateRoutingPluginConfig(registry, *cfg)
	if err != nil {
		return scanRoutePlan{}, err
	}
	plan := scanRoutePlan{Valid: true, Validation: validation}
	runtimeCfg, runtimeOK := buildRouteRuntimeConfig(*cfg, validation)
	if runtimeOK {
		plan.RuntimeCfg = runtimeCfg
	}
	return plan, nil
}

func (p scanRoutePlan) Public() any {
	if !p.Valid {
		return nil
	}
	return p.Validation
}

func (p scanRoutePlan) ApplyRequestedToResult(res *result) {
	if res == nil || !p.Valid {
		return
	}
	res.RouteID = p.Validation.RouteID
	res.RequestedRouteID = p.Validation.RouteID
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = false
	res.RouteReadinessSource = "validation_template"
	if p.HasRuntimeRoute() {
		res.RouteEvidenceState = "requested_runtime_pending_observation"
	} else {
		res.RouteEvidenceState = "requested_observer_only"
	}
}

func (p scanRoutePlan) HasRuntimeRoute() bool {
	return p.Valid && p.RuntimeCfg != nil
}

func (p scanRoutePlan) RouteConfigForProbe(timeoutMS int) RouteConfig {
	cfg := *p.RuntimeCfg
	cfg.Timeout = time.Duration(timeoutMS) * time.Millisecond
	return cfg
}

func (p scanRoutePlan) RuntimeUnavailableError() (string, string, map[string]any) {
	if !p.Valid || p.HasRuntimeRoute() {
		return "", "", nil
	}
	code := "ROUTE_NOT_READY"
	if p.Validation.RouteBinding == "external_vpn_observation" || p.Validation.RouteBinding == "profile_backed_vpn_or_proxy" {
		code = "ROUTE_UNSUPPORTED"
	}
	message := "requested route plugin cannot provide an attachable runtime dial path"
	if code == "ROUTE_UNSUPPORTED" {
		message = "requested route plugin mode is observation-only and cannot be attached to scan dialing"
	}
	details := map[string]any{
		"requested_route_id": p.Validation.RouteID,
		"plugin_id":          p.Validation.PluginID,
		"plugin_type":        p.Validation.PluginType,
		"route_binding":      p.Validation.RouteBinding,
		"protocol_mode":      p.Validation.ProtocolMode,
		"attachable":         p.Validation.Attachable,
		"readiness_probe":    p.Validation.ReadinessProbe,
	}
	return code, message, details
}

func (p scanRoutePlan) ApplyObservedToResult(res *result, obs *RouteObservation) {
	if res == nil || !p.Valid || obs == nil {
		return
	}
	res.RouteUsed = strings.EqualFold(obs.Status, "success")
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = true
	res.ObservedRouteID = obs.RouteID
	res.ObservedRouteType = string(obs.RouteType)
	if res.RouteID == "" {
		res.RouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID == "" {
		res.RequestedRouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID != "" && res.ObservedRouteID != "" && res.RequestedRouteID != res.ObservedRouteID {
		res.RouteMismatchCode = "ROUTE_REQUEST_OBSERVATION_MISMATCH"
	}
	if res.RouteUsed {
		res.RouteEvidenceState = "observed_attached"
	} else {
		res.RouteEvidenceState = "observed_failed"
	}
	res.RouteID = obs.RouteID
	res.RouteProviderID = obs.ProviderID
	res.RouteBinding = obs.RouteBinding
	res.RouteProtocolMode = obs.ProtocolMode
	res.RouteAuthMode = obs.AuthMode
	res.RouteDNSPolicy = obs.DNSPolicy
	res.RouteReadiness = obs.Status
	res.RouteReadinessSource = "observation"
	if obs.ErrorCode != "" {
		res.RouteErrorCode = obs.ErrorCode
	}
	res.RouteStrategy = p.Validation.RouteStrategy
	res.RouteProviderChain = p.Validation.ProviderChain
	res.RouteFrontingPolicy = p.Validation.FrontingPolicy
	res.RouteLANSharing = p.Validation.LANSharing
	res.RouteBeastMode = p.Validation.BeastMode
}

func (p scanRoutePlan) ApplyRouteNotObserved(res *result) {
	if res == nil || !p.Valid {
		return
	}
	if res.RouteID == "" {
		res.RouteID = p.Validation.RouteID
	}
	if res.RequestedRouteID == "" {
		res.RequestedRouteID = p.Validation.RouteID
	}
	res.RouteUsed = false
	res.RouteConfigReady = true
	res.RouteDialerReady = p.HasRuntimeRoute()
	res.RouteObserved = false
	res.RouteReadiness = p.Validation.Observation.ReadinessState
	res.RouteReadinessSource = "validation_template"
	if p.HasRuntimeRoute() {
		res.RouteEvidenceState = "requested_runtime_not_observed"
		res.RouteMismatchCode = "ROUTE_REQUEST_NOT_OBSERVED"
		if res.RouteErrorCode == "" {
			res.RouteErrorCode = "ROUTE_REQUEST_NOT_OBSERVED"
		}
		return
	}
	res.RouteEvidenceState = "requested_observer_only"
}

func buildRouteRuntimeConfig(cfg RoutingPluginConfig, validation RoutingPluginConfigValidation) (*RouteConfig, bool) {
	if !validation.Valid || !validation.Attachable {
		return nil, false
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, false
	}
	if err := validateProxyEndpoint(endpoint); err != nil {
		return nil, false
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return nil, false
	}
	var routeType RouteType
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "socks5":
		routeType = RouteSOCKS5
	case "http", "http-connect":
		routeType = RouteHTTPConnect
	default:
		return nil, false
	}
	runtimeCfg := &RouteConfig{
		RouteID:        cfg.RouteID,
		Type:           routeType,
		ProxyAddress:   parsed.Host,
		DNSPolicy:      validation.DNSPolicy,
		Timeout:        time.Second,
		ProviderID:     firstNonEmpty(validation.PluginID, validation.PluginType),
		RouteBinding:   validation.RouteBinding,
		ProtocolMode:   validation.ProtocolMode,
		AuthMode:       validation.AuthMode,
		SplitTunnel:    validation.SplitTunnel,
		UpstreamMode:   validation.UpstreamMode,
		DownstreamMode: validation.DownstreamMode,
	}
	return runtimeCfg, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
