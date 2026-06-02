package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"
)

func buildSidecarMux(control *sidecarControlPlane) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/grafana-dashboard.json", grafanaDashboard)
	mux.HandleFunc("/api/scan", control.requireMutationAuth(scan))
	mux.HandleFunc("/api/dns", control.requireMutationAuth(scanDNS))
	mux.HandleFunc("/api/stop", control.requireMutationAuth(control.stop))
	mux.HandleFunc("/api/shutdown", control.requireMutationAuth(control.shutdown))
	mux.HandleFunc("/api/heartbeat", control.requireReadAuth(control.heartbeat))
	mux.HandleFunc("/api/plugins", routingPlugins)
	mux.HandleFunc("/api/plugins/validate", control.requireMutationAuth(validateRoutingPlugin))
	mux.HandleFunc("/api/provider-corpus", providerCorpusStatusHandler)
	mux.HandleFunc("/api/export/nmap", control.requireMutationAuth(exportNmap))
	mux.HandleFunc("/metrics", control.requireReadAuth(metrics))
	mux.HandleFunc("/health", control.requireReadAuth(func(w http.ResponseWriter, _ *http.Request) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "time": time.Now().Format(time.RFC3339),
			"goroutines": runtime.NumGoroutine(), "heap_bytes": mem.HeapAlloc,
		})
	}))
	return mux
}

func runSidecarServer(addr string, mux *http.ServeMux, control *sidecarControlPlane, serviceName string) {
	srv := &http.Server{Addr: addr, Handler: mux}
	control.setShutdown(srv.Shutdown)
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignals()
	go func() {
		<-ctx.Done()
		activeCancelMu.Lock()
		if activeCancel != nil {
			activeCancel()
		}
		activeCancelMu.Unlock()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn(serviceName+" sidecar graceful shutdown failed", "error", err)
		}
	}()
	slog.Info(serviceName+" sidecar listening", "url", "http://"+addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error(serviceName+" sidecar stopped", "error", err)
		os.Exit(1)
	}
	slog.Info(serviceName + " sidecar stopped")
}
