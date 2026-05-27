package main

import (
	"encoding/json"
	"testing"
)

func TestLegacyProviderObserverMatchesCloudflareIPv4(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("104.16.1.1")
	if got.ProviderID != "cloudflare" || got.Prefix != "104.16.0.0/12" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestLegacyProviderObserverMatchesAkamaiIPv6(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("2a02:26f0::1")
	if got.ProviderID != "akamai" || got.Prefix != "2a02:26f0::/32" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestLegacyProviderObserverUnknown(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	got := observeProvider("203.0.113.7")
	if got.ProviderID != "" {
		t.Fatalf("unexpected provider observation: %+v", got)
	}
}

func TestProviderObservationAppliesToResultJSONWithoutChangingLegacyCDN(t *testing.T) {
	if err := initProviderCorpusObserver(); err != nil {
		t.Fatalf("initProviderCorpusObserver failed: %v", err)
	}
	res := result{CDN: "cloudflare"}
	res.applyProviderObservation(observeProvider("104.16.1.1"))
	if res.CDN != "cloudflare" {
		t.Fatalf("legacy CDN changed: %q", res.CDN)
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
	if payload["cdn"] != "cloudflare" {
		t.Fatalf("legacy cdn field missing from JSON: %v", payload)
	}
}
