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
