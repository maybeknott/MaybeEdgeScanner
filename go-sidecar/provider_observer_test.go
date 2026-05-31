package main

import (
	"encoding/json"
	"testing"
)

func TestBuiltinProviderObserverMatchesCloudflareIPv4(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("104.16.1.1")
	if got.ProviderID != "cloudflare" || got.Prefix != "104.16.0.0/12" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestBuiltinProviderObserverMatchesAkamaiIPv6(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("2a02:26f0::1")
	if got.ProviderID != "akamai" || got.Prefix != "2a02:26f0::/32" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestBuiltinProviderObserverUnknown(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("203.0.113.7")
	if got.ProviderID != "" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestProviderObservationAppliesToResultJSONWithoutChangingNetworkClassification(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	res := result{NetworkClassification: "cloudflare"}
	res.applyProviderObservation(observeProvider("104.16.1.1"))
	if res.NetworkClassification != "cloudflare" {
		t.Fatalf("network classification changed: %q", res.NetworkClassification)
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal result failed: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("Unmarshal result failed: %v", err)
	}
	if payload["provider_id"] != "cloudflare" || payload["provider_prefix"] != "104.16.0.0/12" {
		t.Fatalf("provider fields missing from JSON: %v", payload)
	}
	if payload["network_classification"] != "cloudflare" {
		t.Fatalf("network_classification missing from JSON: %v", payload)
	}
	if _, ok := payload["cdn"]; ok {
		t.Fatalf("retired cdn field should not be emitted: %v", payload)
	}
}
