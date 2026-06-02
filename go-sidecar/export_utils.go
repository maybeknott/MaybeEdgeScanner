package main

import (
	"fmt"
	"strings"
)

func xmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

func nmapHostScripts(row result) string {
	var scripts []string
	if row.TargetPlan != nil {
		addNmapScript(&scripts, "maybeedgescanner-target-plan", joinScriptFields(map[string]string{
			"plan_id":                row.TargetPlan.PlanID,
			"correlation_id":         row.TargetPlan.ResultCorrelationID,
			"product_mode":           row.TargetPlan.ProductMode,
			"raw_token":              row.TargetPlan.RawToken,
			"original_hostname":      row.TargetPlan.OriginalHostname,
			"resolved_ip":            row.TargetPlan.ResolvedIP,
			"sni_mode":               row.TargetPlan.SNIMode,
			"route_id":               row.TargetPlan.RouteID,
			"route_type":             row.TargetPlan.RouteType,
			"dedupe_key":             row.TargetPlan.DedupeKey,
			"expansion_parent":       row.TargetPlan.ExpansionParent,
			"expansion_index":        intPointerString(row.TargetPlan.ExpansionIndex),
			"expansion_total_capped": int64PointerString(row.TargetPlan.ExpansionTotalCapped),
		}))
	}
	addNmapScript(&scripts, "maybeedgescanner-result-correlation", joinScriptFields(map[string]string{
		"plan_id":            row.PlanID,
		"correlation_id":     row.ResultCorrelationID,
		"final_phase":        row.FinalPhase,
		"error_code":         row.ErrorCode,
		"requested_route_id": row.RequestedRouteID,
		"observed_route_id":  row.ObservedRouteID,
		"route_error_code":   row.RouteErrorCode,
	}))
	if len(scripts) == 0 {
		return ""
	}
	return "<hostscript>" + strings.Join(scripts, "") + "</hostscript>"
}

func addNmapScript(scripts *[]string, id, output string) {
	if strings.TrimSpace(output) == "" {
		return
	}
	*scripts = append(*scripts, fmt.Sprintf(`<script id="%s" output="%s"/>`, xmlEscape(id), xmlEscape(output)))
}

func joinScriptFields(fields map[string]string) string {
	order := []string{
		"plan_id", "correlation_id", "product_mode", "raw_token", "original_hostname", "resolved_ip",
		"sni_mode", "route_id", "route_type", "dedupe_key", "expansion_parent", "expansion_index",
		"expansion_total_capped", "final_phase", "error_code", "requested_route_id", "observed_route_id",
		"route_error_code",
	}
	var parts []string
	for _, key := range order {
		value := strings.TrimSpace(fields[key])
		if value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func intPointerString(value *int) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func int64PointerString(value *int64) string {
	if value == nil {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}
