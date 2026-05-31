package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionCodeAvoidsRawHTTPErrorResponses(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		content, readErr := os.ReadFile(file)
		if readErr != nil {
			t.Fatalf("read %s failed: %v", file, readErr)
		}
		text := string(content)
		if strings.Contains(text, "http.Error(") {
			t.Fatalf("raw http.Error response found in production file %s; use structured envelope helpers", file)
		}
		if strings.Contains(text, "\"POST required\"") || strings.Contains(text, "\"GET required\"") {
			t.Fatalf("plain-text method error found in production file %s; use METHOD_NOT_ALLOWED envelope", file)
		}
	}
}
