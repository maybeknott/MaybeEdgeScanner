package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	errInvalidScanRequest = errors.New("invalid scan request body")
	errNoUsableTargets    = errors.New("no usable targets")
	errNoTargetsSelected  = errors.New("no targets selected")
)

type sidecarScanRequestV1 struct {
	SchemaVersion int                 `json:"schema_version"`
	RequestID     string              `json:"request_id"`
	ProductMode   string              `json:"product_mode"`
	Plans         []sidecarTargetPlan `json:"plans"`
	ScanOptions   sidecarScanOptions  `json:"scan_options"`
	SafetyPolicy  sidecarSafetyPolicy `json:"safety_policy"`
}

type sidecarTargetPlan struct {
	SchemaVersion             int     `json:"schema_version"`
	PlanID                    string  `json:"plan_id"`
	RawToken                  string  `json:"raw_token"`
	SourceType                string  `json:"source_type"`
	SourceProvider            string  `json:"source_provider"`
	CorpusRevision            string  `json:"corpus_revision"`
	NormalizedKind            string  `json:"normalized_kind"`
	OriginalHostname          string  `json:"original_hostname"`
	ResolvedIP                string  `json:"resolved_ip"`
	IPFamily                  string  `json:"ip_family"`
	Port                      int     `json:"port"`
	SNIHost                   *string `json:"sni_host"`
	SNIMode                   string  `json:"sni_mode"`
	HTTPHost                  *string `json:"http_host"`
	VerificationHost          *string `json:"verification_host"`
	DNSMode                   string  `json:"dns_mode"`
	ResolverID                string  `json:"resolver_id"`
	ALPNPolicy                string  `json:"alpn_policy"`
	RouteID                   string  `json:"route_id"`
	RouteType                 string  `json:"route_type"`
	NetworkPath               string  `json:"network_path"`
	SafetyStatus              string  `json:"safety_status"`
	ExpansionParent           *string `json:"expansion_parent"`
	ExpansionIndex            *int    `json:"expansion_index"`
	ExpansionTotalTheoretical *int64  `json:"expansion_total_theoretical"`
	ExpansionTotalCapped      *int64  `json:"expansion_total_capped"`
	ExpansionSkippedCount     *int64  `json:"expansion_skipped_count"`
	SamplingSeed              string  `json:"sampling_seed"`
	DedupeKey                 string  `json:"dedupe_key"`
	ResultCorrelationID       string  `json:"result_correlation_id"`
}

type sidecarScanOptions struct {
	TimeoutMS          int    `json:"timeout_ms"`
	ConnectTimeoutMS   int    `json:"connect_timeout_ms"`
	TLSTimeoutMS       int    `json:"tls_timeout_ms"`
	HTTPTimeoutMS      int    `json:"http_timeout_ms"`
	Threads            int    `json:"threads"`
	HTTPProbe          bool   `json:"http_probe"`
	HTTPPath           string `json:"http_path"`
	HTTPProtocolPolicy string `json:"http_protocol_policy"`
	BodyLimitBytes     int    `json:"body_limit_bytes"`
	ResultStream       string `json:"result_stream"`
}

type sidecarSafetyPolicy struct {
	RespectReservedRanges bool `json:"respect_reserved_ranges"`
	MaxPlans              int  `json:"max_plans"`
	MaxCIDRHosts          int  `json:"max_cidr_hosts"`
	RatePerSecond         int  `json:"rate_per_second"`
	JitterMS              int  `json:"jitter_ms"`
}

type planWorkItem struct {
	target        string
	ip            string
	port          int
	sni           string
	sniMode       string
	planID        string
	routeID       string
	correlationID string
	targetPlan    TargetPlanEvidence
}

func decodeSidecarScanRequestV1(body []byte) (sidecarScanRequestV1, bool) {
	var req sidecarScanRequestV1
	if err := json.Unmarshal(body, &req); err != nil {
		return sidecarScanRequestV1{}, false
	}
	if req.SchemaVersion != 1 || len(req.Plans) == 0 {
		return sidecarScanRequestV1{}, false
	}
	return req, true
}

func (r sidecarScanRequestV1) toScanRequest() scanRequest {
	return scanRequest{
		HTTPPath:      r.ScanOptions.HTTPPath,
		Threads:       r.ScanOptions.Threads,
		TimeoutMS:     r.ScanOptions.TimeoutMS,
		MaxCIDRHosts:  r.SafetyPolicy.MaxCIDRHosts,
		BatchSize:     12000,
		HTTPProbe:     r.ScanOptions.HTTPProbe,
		RatePerSecond: r.SafetyPolicy.RatePerSecond,
		JitterMS:      r.SafetyPolicy.JitterMS,
		RespectSafety: r.SafetyPolicy.RespectReservedRanges,
	}
}

func (r sidecarScanRequestV1) planWorkItems() []planWorkItem {
	maxPlans := r.SafetyPolicy.MaxPlans
	items := make([]planWorkItem, 0, len(r.Plans))
	for _, plan := range r.Plans {
		if strings.EqualFold(strings.TrimSpace(plan.SafetyStatus), "excluded") {
			continue
		}
		port := plan.Port
		if port <= 0 {
			port = 443
		}
		sni := ""
		if plan.SNIHost != nil {
			sni = strings.TrimSpace(*plan.SNIHost)
		}
		target := strings.TrimSpace(plan.RawToken)
		if target == "" {
			target = strings.TrimSpace(plan.ResolvedIP)
		}
		items = append(items, planWorkItem{
			target:        target,
			ip:            strings.TrimSpace(plan.ResolvedIP),
			port:          port,
			sni:           sni,
			sniMode:       strings.TrimSpace(plan.SNIMode),
			planID:        strings.TrimSpace(plan.PlanID),
			routeID:       strings.TrimSpace(plan.RouteID),
			correlationID: strings.TrimSpace(plan.ResultCorrelationID),
			targetPlan:    plan.evidence(r.ProductMode, port, sni),
		})
		if maxPlans > 0 && len(items) >= maxPlans {
			break
		}
	}
	return items
}

func (r sidecarScanRequestV1) requestedRouteIDs() []string {
	seen := make(map[string]bool)
	var ids []string
	for _, plan := range r.Plans {
		id := strings.TrimSpace(plan.RouteID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
}

func (item planWorkItem) probeOptions() probeOptions {
	opts := probeOptions{
		FixedIP:             item.ip,
		FixedSNI:            item.sni,
		SNIMode:             item.sniMode,
		PlanID:              item.planID,
		RouteID:             item.routeID,
		ResultCorrelationID: item.correlationID,
	}
	if item.targetPlan.hasIdentity() {
		plan := item.targetPlan
		opts.TargetPlan = &plan
	}
	return opts
}

func (plan sidecarTargetPlan) evidence(productMode string, port int, sni string) TargetPlanEvidence {
	schemaVersion := plan.SchemaVersion
	if schemaVersion <= 0 {
		schemaVersion = 1
	}
	return TargetPlanEvidence{
		SchemaVersion:             schemaVersion,
		PlanID:                    strings.TrimSpace(plan.PlanID),
		ProductMode:               strings.TrimSpace(productMode),
		RawToken:                  strings.TrimSpace(plan.RawToken),
		SourceType:                strings.TrimSpace(plan.SourceType),
		SourceProvider:            strings.TrimSpace(plan.SourceProvider),
		CorpusRevision:            strings.TrimSpace(plan.CorpusRevision),
		NormalizedKind:            strings.TrimSpace(plan.NormalizedKind),
		OriginalHostname:          strings.TrimSpace(plan.OriginalHostname),
		ResolvedIP:                strings.TrimSpace(plan.ResolvedIP),
		IPFamily:                  strings.TrimSpace(plan.IPFamily),
		Port:                      port,
		SNIHost:                   sni,
		SNIMode:                   strings.TrimSpace(plan.SNIMode),
		HTTPHost:                  cleanOptionalString(plan.HTTPHost),
		VerificationHost:          cleanOptionalString(plan.VerificationHost),
		DNSMode:                   strings.TrimSpace(plan.DNSMode),
		ResolverID:                strings.TrimSpace(plan.ResolverID),
		ALPNPolicy:                strings.TrimSpace(plan.ALPNPolicy),
		RouteID:                   strings.TrimSpace(plan.RouteID),
		RouteType:                 strings.TrimSpace(plan.RouteType),
		NetworkPath:               strings.TrimSpace(plan.NetworkPath),
		SafetyStatus:              strings.TrimSpace(plan.SafetyStatus),
		ExpansionParent:           cleanOptionalString(plan.ExpansionParent),
		ExpansionIndex:            plan.ExpansionIndex,
		ExpansionTotalTheoretical: plan.ExpansionTotalTheoretical,
		ExpansionTotalCapped:      plan.ExpansionTotalCapped,
		ExpansionSkippedCount:     plan.ExpansionSkippedCount,
		SamplingSeed:              strings.TrimSpace(plan.SamplingSeed),
		DedupeKey:                 strings.TrimSpace(plan.DedupeKey),
		ResultCorrelationID:       strings.TrimSpace(plan.ResultCorrelationID),
	}
}

func legacyScanWorkItems(targets []string, ports []int, routeID string) []planWorkItem {
	if len(targets) == 0 || len(ports) == 0 {
		return nil
	}
	items := make([]planWorkItem, 0, len(targets)*len(ports))
	trimmedRouteID := strings.TrimSpace(routeID)
	for _, target := range targets {
		t := strings.TrimSpace(target)
		if t == "" {
			continue
		}
		for _, port := range ports {
			if port <= 0 {
				continue
			}
			items = append(items, planWorkItem{
				target:  t,
				port:    port,
				routeID: trimmedRouteID,
			})
		}
	}
	return items
}

type legacyScanPreparation struct {
	req              scanRequest
	routePlan        scanRoutePlan
	targets          []string
	items            []planWorkItem
	warnings         []string
	safetyPolicy     SafetyPolicyObservation
	expansionSummary map[string]any
}

func prepareLegacyScan(bodyBytes []byte) (legacyScanPreparation, error) {
	var req scanRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return legacyScanPreparation{}, fmt.Errorf("%w: %v", errInvalidScanRequest, err)
	}
	req.normalize()
	routePlan, err := validateScanRoutePlugin(req.RoutePlugin)
	if err != nil {
		return legacyScanPreparation{}, err
	}
	if routePlan.Valid && !routePlan.HasRuntimeRoute() {
		return legacyScanPreparation{
			req:       req,
			routePlan: routePlan,
		}, nil
	}
	globalBackoffNS.Store(0)
	explicitTargets := len(req.Targets) > 0
	skippedBefore := metricSafetySkipped.Load()
	targets := expandTargets(req.Targets, req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	expansionSafetySkipped := metricSafetySkipped.Load() - skippedBefore
	if len(targets) == 0 && !explicitTargets {
		targets = expandTargets(loadLines("assets/default_edges_extra.txt"), req.MaxTargets, req.MaxCIDRHosts, req.RespectSafety)
	}
	if len(targets) == 0 && explicitTargets {
		return legacyScanPreparation{}, errNoUsableTargets
	}
	if len(targets) == 0 {
		return legacyScanPreparation{}, errNoTargetsSelected
	}
	if len(req.SNIs) == 0 {
		req.SNIs = loadLines("assets/default_snis.txt")
	}
	if req.MaxTargets > 0 && len(targets) > req.MaxTargets {
		targets = targets[:req.MaxTargets]
	}
	if req.Randomize {
		shuffleStrings(targets)
	}
	safetyPolicy := safetyPolicyObservation(req, len(targets))
	warnings := scanWarnings(req, targets)
	warnings = append(warnings, safetyPolicy.Warnings...)
	if routePlan.Valid {
		if routePlan.HasRuntimeRoute() {
			warnings = append(warnings, "Route plan includes an attachable runtime dial path; requested and observed route IDs are emitted per result.")
		} else {
			warnings = append(warnings, "Route validation is present, but this scan request does not include an attachable runtime route dial path.")
		}
	}
	items := legacyScanWorkItems(targets, req.Ports, routePlan.Validation.RouteID)
	return legacyScanPreparation{
		req:          req,
		routePlan:    routePlan,
		targets:      targets,
		items:        items,
		warnings:     warnings,
		safetyPolicy: safetyPolicy,
		expansionSummary: map[string]any{
			"submitted_tokens": len(req.Targets),
			"expanded_targets": len(targets),
			"safety_skipped":   expansionSafetySkipped,
		},
	}, nil
}
