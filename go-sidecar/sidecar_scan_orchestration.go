package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

func (r *scanRequest) normalize() {
	r.Targets = unique(r.Targets)
	r.SNIs = unique(r.SNIs)
	if r.Threads <= 0 {
		r.Threads = max(4, runtime.NumCPU()*2)
	}
	if r.TimeoutMS <= 0 {
		r.TimeoutMS = 2500
	}
	var ports []int
	for _, port := range r.Ports {
		if port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	r.Ports = ports
	if strings.TrimSpace(r.HTTPPath) == "" {
		r.HTTPPath = "/"
	}
	if !strings.HasPrefix(r.HTTPPath, "/") {
		r.HTTPPath = "/" + r.HTTPPath
	}
	if r.MaxTargets < 0 {
		r.MaxTargets = 0
	}
	if r.MaxCIDRHosts < 0 {
		r.MaxCIDRHosts = 0
	}
	if r.BatchSize <= 0 {
		r.BatchSize = 12000
	}
	if r.RatePerSecond < 0 {
		r.RatePerSecond = 0
	}
	if r.JitterMS < 0 {
		r.JitterMS = 0
	}
	r.applySafetyPreset()
	r.TLSFingerprint = normalizeTLSFingerprint(r.TLSFingerprint)
}

func planProbeOptions(item planWorkItem) probeOptions {
	opts := item.probeOptions()
	opts.RouteID = item.routeID
	return opts
}

func runPlanDrivenScan(w http.ResponseWriter, r *http.Request, v1 sidecarScanRequestV1) {
	metricScansStarted.Add(1)
	if activeControlPlane != nil {
		activeControlPlane.setState("scan_running")
	}
	req := v1.toScanRequest()
	req.normalize()
	globalBackoffNS.Store(0)
	items := v1.planWorkItems()
	if len(items) == 0 {
		writeScanInputError(w, "NO_USABLE_PLANS", "no usable plans after safety filtering", map[string]any{
			"submitted_plan_count": len(v1.Plans),
		})
		return
	}
	if routeIDs := v1.requestedRouteIDs(); len(routeIDs) > 0 {
		writePublicError(w, http.StatusConflict, "ROUTE_UNSUPPORTED", "plan-driven scan route_id requires an attachable route_plugin runtime path", map[string]any{
			"requested_route_ids": routeIDs,
			"request_id":          v1.RequestID,
			"product_mode":        v1.ProductMode,
			"attachable":          false,
		})
		return
	}
	safetyPolicy := safetyPolicyObservation(req, len(items))
	warnings := scanWarnings(req, nil)
	warnings = append(warnings, safetyPolicy.Warnings...)
	expansionSummary := map[string]any{
		"submitted_plans": len(v1.Plans),
		"usable_plans":    len(items),
		"request_id":      v1.RequestID,
		"product_mode":    v1.ProductMode,
	}
	runScanWorkItems(w, r, req, items, warnings, safetyPolicy, expansionSummary, scanRoutePlan{})
}

func runScanWorkItems(w http.ResponseWriter, r *http.Request, req scanRequest, items []planWorkItem, warnings []string, safetyPolicy SafetyPolicyObservation, expansionSummary map[string]any, routePlan scanRoutePlan) {
	var serial uint64
	ctx, cancel := context.WithCancel(r.Context())
	activeCancelMu.Lock()
	if activeCancel != nil {
		activeCancel()
	}
	activeSerial++
	serial = activeSerial
	activeCancel = cancel
	activeCancelMu.Unlock()
	defer func() {
		activeCancelMu.Lock()
		if activeSerial == serial {
			activeCancel = nil
		}
		activeCancelMu.Unlock()
		globalBackoffNS.Store(0)
		cancel()
	}()

	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	jobsTotal := len(items)
	st := stats{Total: jobsTotal, Batches: int(math.Ceil(float64(len(items)) / float64(req.BatchSize)))}
	if err := enc.Encode(map[string]any{"type": "init", "total": st.Total, "batches": st.Batches, "warnings": warnings, "safety_policy": safetyPolicy, "expansion": expansionSummary, "route_plugin": routePlan.Public()}); err != nil {
		cancel()
		return
	}
	flush(flusher)

	var checked atomic.Int64
	var working atomic.Int64
	var tlsWorking atomic.Int64
	var httpWorking atomic.Int64
	var down atomic.Int64

	limiter := newRateLimiter(req.RatePerSecond)
	recentErrors := newErrorRingBuffer(64)
	for start, batchNo := 0, 1; start < len(items) && ctx.Err() == nil; start, batchNo = start+req.BatchSize, batchNo+1 {
		end := min(len(items), start+req.BatchSize)
		results := runScanBatch(
			ctx,
			items[start:end],
			req.Threads,
			req.BatchSize,
			limiter,
			req.JitterMS,
			func(item planWorkItem) result {
				return probe(ctx, item.target, item.port, req, batchNo, routePlan, planProbeOptions(item))
			},
		)
		for res := range results {
			if err := emitScanProgress(enc, flusher, res, st, batchNo, &checked, &working, &tlsWorking, &httpWorking, &down, recentErrors, req.RatePerSecond); err != nil {
				cancel()
				return
			}
		}
	}
	if ctx.Err() == nil {
		metricScansCompleted.Add(1)
	}
	if err := enc.Encode(map[string]any{"type": "done", "stopped": ctx.Err() != nil}); err != nil {
		cancel()
		return
	}
	flush(flusher)
}

func runScanBatch(
	ctx context.Context,
	items []planWorkItem,
	threads int,
	batchSize int,
	limiter *rate.Limiter,
	jitterMS int,
	probeOne func(planWorkItem) result,
) <-chan result {
	results := make(chan result, resultBufferSize(batchSize))
	jobs := make(chan planWorkItem)
	var wg sync.WaitGroup
	for i := 0; i < min(threads, len(items)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				if backoffDelay := globalBackoffNS.Load(); backoffDelay > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Duration(backoffDelay)):
					}
				}
				waitRate(ctx, limiter, jitterMS)
				res := probeOne(item)
				select {
				case <-ctx.Done():
					return
				case results <- res:
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, item := range items {
			select {
			case <-ctx.Done():
				return
			case jobs <- item:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func emitScanProgress(
	enc *json.Encoder,
	flusher http.Flusher,
	res result,
	st stats,
	batchNo int,
	checked *atomic.Int64,
	working *atomic.Int64,
	tlsWorking *atomic.Int64,
	httpWorking *atomic.Int64,
	down *atomic.Int64,
	recentErrors *errorRingBuffer,
	ratePerSecond int,
) error {
	c := int(checked.Add(1))
	metricScanResults.Add(1)
	if res.TCP || res.TLS || res.HTTP {
		working.Add(1)
	} else {
		down.Add(1)
	}
	if res.TLS {
		metricTLSPass.Add(1)
		tlsWorking.Add(1)
	}
	if res.HTTP {
		metricHTTPPass.Add(1)
		httpWorking.Add(1)
	}
	if res.TCP {
		metricTCPPass.Add(1)
	}
	if resultIndicatesTimeout(res) {
		metricTimeouts.Add(1)
	}
	if resultIndicatesReset(res) {
		metricResets.Add(1)
	}
	if res.Error != "" {
		recentErrors.Append(res.Error)
		trackAdaptiveBackoff(recentErrors.Snapshot(), ratePerSecond)
	}
	payloadStats := stats{
		Total: st.Total, Checked: c, Working: int(working.Load()),
		TLSWorking: int(tlsWorking.Load()), HTTPWorking: int(httpWorking.Load()),
		Down: int(down.Load()), Batches: st.Batches, Batch: batchNo,
	}
	if err := enc.Encode(map[string]any{"type": "progress", "result": res, "stats": payloadStats}); err != nil {
		return err
	}
	flush(flusher)
	return nil
}
