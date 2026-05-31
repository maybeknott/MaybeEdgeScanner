package main

import (
	"encoding/json"
	"strings"
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
	PlanID              string  `json:"plan_id"`
	RawToken            string  `json:"raw_token"`
	ResolvedIP          string  `json:"resolved_ip"`
	Port                int     `json:"port"`
	SNIHost             *string `json:"sni_host"`
	SNIMode             string  `json:"sni_mode"`
	RouteID             string  `json:"route_id"`
	ResultCorrelationID string  `json:"result_correlation_id"`
	DNSMode             string  `json:"dns_mode"`
	SafetyStatus        string  `json:"safety_status"`
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
			correlationID: strings.TrimSpace(plan.ResultCorrelationID),
		})
		if maxPlans > 0 && len(items) >= maxPlans {
			break
		}
	}
	return items
}

func (item planWorkItem) probeOptions() probeOptions {
	return probeOptions{
		FixedIP:             item.ip,
		FixedSNI:            item.sni,
		SNIMode:             item.sniMode,
		PlanID:              item.planID,
		ResultCorrelationID: item.correlationID,
	}
}
