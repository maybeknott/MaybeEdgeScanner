package main

import (
	"log/slog"
	"os"
)

func main() {
	initNetworkClassificationIndex()
	if err := initProviderCorpusObserver(); err != nil {
		slog.Warn("provider corpus observer disabled", "error", err)
	}
	control, err := newSidecarControlPlane()
	if err != nil {
		slog.Error("sidecar control-plane initialization failed", "error", err)
		os.Exit(1)
	}
	activeControlPlane = control
	mux := buildSidecarMux(control)
	addr := "127.0.0.1:10808"
	runSidecarServer(addr, mux, control, "MaybeEdgeScanner")
}
