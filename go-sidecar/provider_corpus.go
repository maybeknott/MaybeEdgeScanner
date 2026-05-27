package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

type ProviderCorpus struct {
	SchemaVersion    int                `json:"schema_version"`
	CorpusID         string             `json:"corpus_id"`
	GeneratorVersion string             `json:"generator_version"`
	GeneratedAt      string             `json:"generated_at"`
	FetchedAt        string             `json:"fetched_at"`
	StaleAfter       string             `json:"stale_after"`
	Checksum         string             `json:"checksum"`
	Providers        []ProviderManifest `json:"providers"`
}

type ProviderManifest struct {
	ProviderID    string   `json:"provider_id"`
	DisplayName   string   `json:"display_name"`
	SourceURL     string   `json:"source_url"`
	SourceLicense string   `json:"source_license"`
	SourceKind    string   `json:"source_kind"`
	Confidence    string   `json:"confidence"`
	Priority      int      `json:"priority"`
	IPv4Prefixes  []string `json:"ipv4_prefixes"`
	IPv6Prefixes  []string `json:"ipv6_prefixes"`
	ASNTags       []string `json:"asn_tags"`
	RegionTags    []string `json:"region_tags"`
}

type ProviderMatch struct {
	ProviderID    string
	DisplayName   string
	Prefix        netip.Prefix
	Confidence    string
	Priority      int
	CorpusID      string
	SourceURL     string
	SourceLicense string
}

type providerPrefixRecord struct {
	prefix        netip.Prefix
	providerID    string
	displayName   string
	confidence    string
	priority      int
	sourceURL     string
	sourceLicense string
}

type ProviderSnapshot struct {
	CorpusID         string
	GeneratorVersion string
	GeneratedAt      string
	FetchedAt        string
	StaleAfter       string
	Checksum         string
	records          []providerPrefixRecord
}

type ProviderCorpusStatus struct {
	SchemaVersion    int    `json:"schema_version"`
	CorpusID         string `json:"corpus_id"`
	GeneratorVersion string `json:"generator_version"`
	GeneratedAt      string `json:"generated_at"`
	FetchedAt        string `json:"fetched_at"`
	StaleAfter       string `json:"stale_after"`
	Checksum         string `json:"checksum"`
	Stale            bool   `json:"stale"`
}

type ProviderCorpusStore struct {
	value atomic.Value
}

func ParseProviderCorpus(data []byte) (ProviderCorpus, error) {
	var corpus ProviderCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return ProviderCorpus{}, err
	}
	if err := validateProviderCorpus(corpus); err != nil {
		return ProviderCorpus{}, err
	}
	return corpus, nil
}

func validateProviderCorpus(corpus ProviderCorpus) error {
	if corpus.SchemaVersion != 1 {
		return fmt.Errorf("unsupported provider corpus schema_version %d", corpus.SchemaVersion)
	}
	if corpus.CorpusID == "" || corpus.Checksum == "" || corpus.GeneratorVersion == "" {
		return fmt.Errorf("provider corpus missing identity fields")
	}
	seen := map[string]bool{}
	for _, provider := range corpus.Providers {
		if provider.ProviderID == "" {
			return fmt.Errorf("provider missing provider_id")
		}
		if seen[provider.ProviderID] {
			return fmt.Errorf("duplicate provider_id %q", provider.ProviderID)
		}
		seen[provider.ProviderID] = true
		if len(provider.IPv4Prefixes)+len(provider.IPv6Prefixes) == 0 {
			return fmt.Errorf("provider %q has no prefixes", provider.ProviderID)
		}
		for _, raw := range append(append([]string{}, provider.IPv4Prefixes...), provider.IPv6Prefixes...) {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("provider %q invalid prefix %q: %w", provider.ProviderID, raw, err)
			}
		}
	}
	return nil
}

func BuildProviderSnapshot(corpus ProviderCorpus) (*ProviderSnapshot, error) {
	if err := validateProviderCorpus(corpus); err != nil {
		return nil, err
	}
	snapshot := &ProviderSnapshot{
		CorpusID:         corpus.CorpusID,
		GeneratorVersion: corpus.GeneratorVersion,
		GeneratedAt:      corpus.GeneratedAt,
		FetchedAt:        corpus.FetchedAt,
		StaleAfter:       corpus.StaleAfter,
		Checksum:         corpus.Checksum,
	}
	for _, provider := range corpus.Providers {
		for _, raw := range append(append([]string{}, provider.IPv4Prefixes...), provider.IPv6Prefixes...) {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, err
			}
			snapshot.records = append(snapshot.records, providerPrefixRecord{
				prefix:        prefix.Masked(),
				providerID:    provider.ProviderID,
				displayName:   provider.DisplayName,
				confidence:    provider.Confidence,
				priority:      provider.Priority,
				sourceURL:     provider.SourceURL,
				sourceLicense: provider.SourceLicense,
			})
		}
	}
	sort.SliceStable(snapshot.records, func(i, j int) bool {
		a := snapshot.records[i]
		b := snapshot.records[j]
		if a.prefix.Bits() != b.prefix.Bits() {
			return a.prefix.Bits() > b.prefix.Bits()
		}
		return a.priority > b.priority
	})
	return snapshot, nil
}

func (snapshot *ProviderSnapshot) Lookup(addr netip.Addr) (ProviderMatch, bool) {
	if snapshot == nil || !addr.IsValid() {
		return ProviderMatch{}, false
	}
	for _, record := range snapshot.records {
		if record.prefix.Contains(addr) {
			return ProviderMatch{
				ProviderID:    record.providerID,
				DisplayName:   record.displayName,
				Prefix:        record.prefix,
				Confidence:    record.confidence,
				Priority:      record.priority,
				CorpusID:      snapshot.CorpusID,
				SourceURL:     record.sourceURL,
				SourceLicense: record.sourceLicense,
			}, true
		}
	}
	return ProviderMatch{}, false
}

func (store *ProviderCorpusStore) Store(snapshot *ProviderSnapshot) {
	store.value.Store(snapshot)
}

func (store *ProviderCorpusStore) Lookup(addr netip.Addr) (ProviderMatch, bool) {
	value := store.value.Load()
	if value == nil {
		return ProviderMatch{}, false
	}
	snapshot, ok := value.(*ProviderSnapshot)
	if !ok {
		return ProviderMatch{}, false
	}
	return snapshot.Lookup(addr)
}

func (store *ProviderCorpusStore) Status(now time.Time) (ProviderCorpusStatus, bool) {
	value := store.value.Load()
	if value == nil {
		return ProviderCorpusStatus{}, false
	}
	snapshot, ok := value.(*ProviderSnapshot)
	if !ok || snapshot == nil {
		return ProviderCorpusStatus{}, false
	}
	status := ProviderCorpusStatus{
		SchemaVersion:    1,
		CorpusID:         snapshot.CorpusID,
		GeneratorVersion: snapshot.GeneratorVersion,
		GeneratedAt:      snapshot.GeneratedAt,
		FetchedAt:        snapshot.FetchedAt,
		StaleAfter:       snapshot.StaleAfter,
		Checksum:         snapshot.Checksum,
	}
	if snapshot.StaleAfter != "" {
		if staleAfterAt, err := time.Parse(time.RFC3339, snapshot.StaleAfter); err == nil && now.After(staleAfterAt) {
			status.Stale = true
		}
	}
	return status, true
}
