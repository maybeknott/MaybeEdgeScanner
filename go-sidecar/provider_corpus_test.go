package main

import (
	"net/netip"
	"testing"
	"time"
)

func testProviderCorpus() ProviderCorpus {
	return ProviderCorpus{
		SchemaVersion:    1,
		CorpusID:         "test-corpus",
		GeneratorVersion: "test",
		GeneratedAt:      "2026-05-24T00:00:00Z",
		FetchedAt:        "2026-05-24T00:00:00Z",
		StaleAfter:       "2026-06-23T00:00:00Z",
		Checksum:         "sha256:test",
		Providers: []ProviderManifest{
			{
				ProviderID:    "provider-wide",
				DisplayName:   "Provider Wide",
				SourceURL:     "fixture://wide",
				SourceLicense: "fixture",
				SourceKind:    "manual_fixture",
				Confidence:    "high",
				Priority:      100,
				IPv4Prefixes:  []string{"198.51.100.0/24"},
				IPv6Prefixes:  []string{"2001:db8:100::/48"},
			},
			{
				ProviderID:    "provider-edge",
				DisplayName:   "Provider Edge",
				SourceURL:     "fixture://edge",
				SourceLicense: "fixture",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      50,
				IPv4Prefixes:  []string{"198.51.100.128/25"},
				IPv6Prefixes:  []string{"2001:db8:100:1::/64"},
			},
		},
	}
}

func TestProviderSnapshotLongestPrefixIPv4(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("198.51.100.200"))
	if !ok {
		t.Fatal("expected provider match")
	}
	if match.ProviderID != "provider-edge" || match.Prefix.String() != "198.51.100.128/25" {
		t.Fatalf("unexpected match: %+v", match)
	}
}

func TestProviderSnapshotIPv6(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("2001:db8:100:1::5"))
	if !ok {
		t.Fatal("expected provider match")
	}
	if match.ProviderID != "provider-edge" || match.Prefix.String() != "2001:db8:100:1::/64" {
		t.Fatalf("unexpected match: %+v", match)
	}
}

func TestProviderSnapshotUnknown(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	if _, ok := snapshot.Lookup(netip.MustParseAddr("203.0.113.10")); ok {
		t.Fatal("unexpected provider match")
	}
}

func TestProviderCorpusStoreAtomicSwap(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	var store ProviderCorpusStore
	store.Store(snapshot)
	match, ok := store.Lookup(netip.MustParseAddr("198.51.100.7"))
	if !ok {
		t.Fatal("expected provider match")
	}
	if match.ProviderID != "provider-wide" {
		t.Fatalf("unexpected match: %+v", match)
	}
}

func TestProviderCorpusStatusIncludesMetadata(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	var store ProviderCorpusStore
	store.Store(snapshot)
	status, ok := store.Status(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected provider corpus status")
	}
	if status.SchemaVersion != 1 || status.CorpusID != "test-corpus" || status.GeneratorVersion != "test" {
		t.Fatalf("unexpected status metadata: %+v", status)
	}
	if status.Stale {
		t.Fatalf("unexpected stale status: %+v", status)
	}
}

func TestProviderCorpusStatusMarksStale(t *testing.T) {
	snapshot, err := BuildProviderSnapshot(testProviderCorpus())
	if err != nil {
		t.Fatalf("BuildProviderSnapshot failed: %v", err)
	}
	var store ProviderCorpusStore
	store.Store(snapshot)
	status, ok := store.Status(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("expected provider corpus status")
	}
	if !status.Stale {
		t.Fatalf("expected stale status: %+v", status)
	}
}
