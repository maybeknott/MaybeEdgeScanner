package main

import (
	"reflect"
	"testing"
)

func TestCandidateSNIsKeepsTargetsAndCorpusSeparate(t *testing.T) {
	corpus := []string{"cdn.example", "front.example", "cdn.example"}
	cases := []struct {
		name        string
		resolvedSNI string
		multi       bool
		want        []string
	}{
		{name: "domain single mode uses resolved host", resolvedSNI: "target.example", multi: false, want: []string{"target.example"}},
		{name: "ip single mode uses primary corpus sni", resolvedSNI: "", multi: false, want: []string{"cdn.example"}},
		{name: "domain multi mode tests target then corpus", resolvedSNI: "target.example", multi: true, want: []string{"target.example", "cdn.example", "front.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := candidateSNIs(tc.resolvedSNI, corpus, tc.multi); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidateSNIs()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestExpandTargetsExpandsIPv4RangesAndSmallCIDRs(t *testing.T) {
	got := expandTargets([]string{"203.0.113.7-203.0.113.9", "198.51.100.42/32"}, 10, 10, false)
	want := []string{"203.0.113.7", "203.0.113.8", "203.0.113.9", "198.51.100.42"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandTargets()=%v, want %v", got, want)
	}
}

func TestExpandRangeHonorsSafety(t *testing.T) {
	got := expandTargets([]string{"192.168.1.1-192.168.1.3"}, 10, 10, true)
	if len(got) != 0 {
		t.Fatalf("expandTargets()=%v, want private range skipped", got)
	}
}
