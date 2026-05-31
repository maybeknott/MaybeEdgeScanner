package main

import "net/netip"

var providerCorpusStore ProviderCorpusStore

type ProviderObservation struct {
	ProviderID  string `json:"provider_id,omitempty"`
	DisplayName string `json:"provider_name,omitempty"`
	Prefix      string `json:"provider_prefix,omitempty"`
	Confidence  string `json:"provider_confidence,omitempty"`
	CorpusID    string `json:"provider_corpus_id,omitempty"`
	Source      string `json:"provider_source,omitempty"`
}

func initProviderCorpusObserver() error {
	snapshot, err := BuildProviderSnapshot(builtinProviderCorpus())
	if err != nil {
		return err
	}
	providerCorpusStore.Store(snapshot)
	return nil
}

func builtinProviderCorpus() ProviderCorpus {
	return ProviderCorpus{
		SchemaVersion:    1,
		CorpusID:         "builtin-provider-prefixes-v1",
		GeneratorVersion: "manual-builtin-provider-prefixes-v1",
		GeneratedAt:      "2026-05-24T00:00:00Z",
		FetchedAt:        "2026-05-24T00:00:00Z",
		StaleAfter:       "2026-06-23T00:00:00Z",
		Checksum:         "manual:builtin-provider-prefixes-v1",
		Providers: []ProviderManifest{
			{
				ProviderID:    "cloudflare",
				DisplayName:   "Cloudflare",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      100,
				IPv4Prefixes:  []string{"104.16.0.0/12", "172.64.0.0/13"},
				IPv6Prefixes:  []string{"2606:4700::/32"},
			},
			{
				ProviderID:    "fastly",
				DisplayName:   "Fastly",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      90,
				IPv4Prefixes:  []string{"151.101.0.0/16"},
				IPv6Prefixes:  []string{"2a04:4e42::/32"},
			},
			{
				ProviderID:    "cloudfront",
				DisplayName:   "Amazon CloudFront",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      80,
				IPv4Prefixes:  []string{"13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "54.230.0.0/16"},
			},
			{
				ProviderID:    "akamai",
				DisplayName:   "Akamai",
				SourceURL:     "builtin://provider_observer",
				SourceLicense: "manual-builtin",
				SourceKind:    "manual_fixture",
				Confidence:    "medium",
				Priority:      70,
				IPv4Prefixes:  []string{"23.32.0.0/11", "23.192.0.0/11", "184.24.0.0/13"},
				IPv6Prefixes:  []string{"2a02:26f0::/32"},
			},
		},
	}
}

func observeProvider(ip string) ProviderObservation {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ProviderObservation{}
	}
	match, ok := providerCorpusStore.Lookup(addr)
	if !ok {
		return ProviderObservation{}
	}
	return ProviderObservation{
		ProviderID:  match.ProviderID,
		DisplayName: match.DisplayName,
		Prefix:      match.Prefix.String(),
		Confidence:  match.Confidence,
		CorpusID:    match.CorpusID,
		Source:      "provider_corpus_observer",
	}
}

func (res *result) applyProviderObservation(observation ProviderObservation) {
	if observation.ProviderID == "" {
		return
	}
	res.ProviderID = observation.ProviderID
	res.ProviderName = observation.DisplayName
	res.ProviderPrefix = observation.Prefix
	res.ProviderConfidence = observation.Confidence
	res.ProviderCorpusID = observation.CorpusID
	res.ProviderSource = observation.Source
}
