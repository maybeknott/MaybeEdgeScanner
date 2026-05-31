package main

import (
	"errors"
	"testing"
)

func TestPhaseStatusFromCode(t *testing.T) {
	if got := phaseStatusFromCode("ROUTE_REQUEST_NOT_OBSERVED", errors.New("x")); got != "failed" {
		t.Fatalf("phaseStatusFromCode()=%q want failed", got)
	}
}

func TestBuildRoutePhaseResult(t *testing.T) {
	res := result{RouteErrorCode: "ROUTE_REQUEST_NOT_OBSERVED", RouteObserved: false}
	phase, ok := buildRoutePhaseResult(res)
	if !ok || phase.Phase != "route" || phase.ErrorCode != "ROUTE_REQUEST_NOT_OBSERVED" {
		t.Fatalf("unexpected route phase %#v ok=%v", phase, ok)
	}
}
