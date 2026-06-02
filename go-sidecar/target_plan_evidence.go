package main

import "strings"

type TargetPlanEvidence struct {
	SchemaVersion             int    `json:"schema_version,omitempty"`
	PlanID                    string `json:"plan_id,omitempty"`
	ProductMode               string `json:"product_mode,omitempty"`
	RawToken                  string `json:"raw_token,omitempty"`
	SourceType                string `json:"source_type,omitempty"`
	SourceProvider            string `json:"source_provider,omitempty"`
	CorpusRevision            string `json:"corpus_revision,omitempty"`
	NormalizedKind            string `json:"normalized_kind,omitempty"`
	OriginalHostname          string `json:"original_hostname,omitempty"`
	ResolvedIP                string `json:"resolved_ip,omitempty"`
	IPFamily                  string `json:"ip_family,omitempty"`
	Port                      int    `json:"port,omitempty"`
	SNIHost                   string `json:"sni_host,omitempty"`
	SNIMode                   string `json:"sni_mode,omitempty"`
	HTTPHost                  string `json:"http_host,omitempty"`
	VerificationHost          string `json:"verification_host,omitempty"`
	DNSMode                   string `json:"dns_mode,omitempty"`
	ResolverID                string `json:"resolver_id,omitempty"`
	ALPNPolicy                string `json:"alpn_policy,omitempty"`
	RouteID                   string `json:"route_id,omitempty"`
	RouteType                 string `json:"route_type,omitempty"`
	NetworkPath               string `json:"network_path,omitempty"`
	SafetyStatus              string `json:"safety_status,omitempty"`
	ExpansionParent           string `json:"expansion_parent,omitempty"`
	ExpansionIndex            *int   `json:"expansion_index,omitempty"`
	ExpansionTotalTheoretical *int64 `json:"expansion_total_theoretical,omitempty"`
	ExpansionTotalCapped      *int64 `json:"expansion_total_capped,omitempty"`
	ExpansionSkippedCount     *int64 `json:"expansion_skipped_count,omitempty"`
	SamplingSeed              string `json:"sampling_seed,omitempty"`
	DedupeKey                 string `json:"dedupe_key,omitempty"`
	ResultCorrelationID       string `json:"result_correlation_id,omitempty"`
}

func (e TargetPlanEvidence) hasIdentity() bool {
	return strings.TrimSpace(e.PlanID) != "" ||
		strings.TrimSpace(e.RawToken) != "" ||
		strings.TrimSpace(e.ResolvedIP) != "" ||
		strings.TrimSpace(e.ResultCorrelationID) != ""
}

func cleanOptionalString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
