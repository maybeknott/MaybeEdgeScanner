package main

import (
	"fmt"
	"net/http"
	"runtime"
)

func writePrometheusMetrics(w http.ResponseWriter, appPrefix string, mem runtime.MemStats) {
	_, _ = fmt.Fprintf(w, "%s_scans_started_total %d\n", appPrefix, metricScansStarted.Load())
	_, _ = fmt.Fprintf(w, "%s_scans_completed_total %d\n", appPrefix, metricScansCompleted.Load())
	_, _ = fmt.Fprintf(w, "%s_results_total %d\n", appPrefix, metricScanResults.Load())
	_, _ = fmt.Fprintf(w, "%s_tcp_pass_total %d\n", appPrefix, metricTCPPass.Load())
	_, _ = fmt.Fprintf(w, "%s_tls_pass_total %d\n", appPrefix, metricTLSPass.Load())
	_, _ = fmt.Fprintf(w, "%s_http_pass_total %d\n", appPrefix, metricHTTPPass.Load())
	_, _ = fmt.Fprintf(w, "%s_timeout_total %d\n", appPrefix, metricTimeouts.Load())
	_, _ = fmt.Fprintf(w, "%s_reset_total %d\n", appPrefix, metricResets.Load())
	_, _ = fmt.Fprintf(w, "%s_dns_runs_total %d\n", appPrefix, metricDNSRuns.Load())
	_, _ = fmt.Fprintf(w, "%s_safety_skipped_total %d\n", appPrefix, metricSafetySkipped.Load())
	_, _ = fmt.Fprintf(w, "%s_backoff_events_total %d\n", appPrefix, metricBackoffEvents.Load())
	_, _ = fmt.Fprintf(w, "%s_goroutines %d\n", appPrefix, runtime.NumGoroutine())
	_, _ = fmt.Fprintf(w, "%s_heap_bytes %d\n", appPrefix, mem.HeapAlloc)
}
