package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/xeipuuv/gojsonschema"
)

func sharedContractSchemaJSON(t *testing.T, schemaFile string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "shared-contracts", "schemas", schemaFile))
	if err != nil {
		t.Fatalf("resolve schema path: %v", err)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read schema %s: %v", schemaFile, err)
	}
	return string(body)
}

func validateAgainstRouteObservationTemplateSchema(t *testing.T, payload any) {
	t.Helper()
	const templateID = "https://maybescanner.local/schemas/route_observation_template.schema.json"
	loader := gojsonschema.NewSchemaLoader()
	if err := loader.AddSchemas(
		gojsonschema.NewStringLoader(sharedContractSchemaJSON(t, "error_code.schema.json")),
		gojsonschema.NewStringLoader(sharedContractSchemaJSON(t, "route_observation.schema.json")),
		gojsonschema.NewStringLoader(sharedContractSchemaJSON(t, "route_observation_template.schema.json")),
	); err != nil {
		t.Fatalf("schema load failed: %v", err)
	}
	schema, err := loader.Compile(gojsonschema.NewReferenceLoader(templateID))
	if err != nil {
		t.Fatalf("schema compile failed: %v", err)
	}
	result, err := schema.Validate(gojsonschema.NewGoLoader(payload))
	if err != nil {
		t.Fatalf("schema validation failed: %v", err)
	}
	if result.Valid() {
		return
	}
	messages := make([]string, 0, len(result.Errors()))
	for _, validationErr := range result.Errors() {
		messages = append(messages, validationErr.String())
	}
	sort.Strings(messages)
	t.Fatalf("route observation template schema mismatch: %s", strings.Join(messages, "; "))
}

func TestRoutingPluginValidationObservationMatchesSharedTemplateSchema(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	result, err := validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-contract",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:windscribe-wireguard",
		CredentialRef: "ref:windscribe-session",
		RemoteDNS:     true,
		Fields: map[string]string{
			"mode":            "wireguard",
			"auth_mode":       "wsnet_session_ref",
			"dns_policy":      "ctrld",
			"downstream_mode": "vpn_interface",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateAgainstRouteObservationTemplateSchema(t, result.Observation)
}

func TestValidateRoutingPluginEndpointObservationMatchesSharedTemplateSchema(t *testing.T) {
	body := bytes.NewBufferString(`{
		"schema_version":1,
		"route_id":"route-windscribe-contract-endpoint",
		"plugin_id":"windscribe",
		"enabled":true,
		"remote_dns":true,
		"profile_ref":"ref:windscribe-wireguard",
		"credential_ref":"ref:windscribe-session",
		"fields":{
			"mode":"wireguard",
			"auth_mode":"wsnet_session_ref",
			"dns_policy":"ctrld",
			"downstream_mode":"vpn_interface"
		}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/validate", body)
	rec := httptest.NewRecorder()
	validateRoutingPlugin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("validate status=%d body=%s", rec.Code, rec.Body.String())
	}
	var result RoutingPluginConfigValidation
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	validateAgainstRouteObservationTemplateSchema(t, result.Observation)
}

func TestValidatePluginFieldMapRejectsTooManyFields(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{
		"mode": "wireguard",
	}
	for i := 0; i < 65; i++ {
		fields["k"+strconv.Itoa(i)] = "x"
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-too-many-fields",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:profile",
		Fields:        fields,
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "too many provider fields") {
		t.Fatalf("expected too-many-fields rejection, got: %v", err)
	}
}

func TestValidatePluginFieldMapRejectsOversizedFieldValue(t *testing.T) {
	registry, err := defaultRoutingPluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	_, err = validateRoutingPluginConfig(registry, RoutingPluginConfig{
		SchemaVersion: 1,
		RouteID:       "route-windscribe-long-value",
		PluginID:      "windscribe",
		Enabled:       true,
		ProfileRef:    "ref:profile",
		Fields: map[string]string{
			"mode":         "wireguard",
			"location_ref": strings.Repeat("a", 4097),
		},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "too long") {
		t.Fatalf("expected field-value-length rejection, got: %v", err)
	}
}
