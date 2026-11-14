package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestCoverageEnvelopeMatchesSARIFRunMetadata(t *testing.T) {
	c := model.NewCoverage()
	c.Processed(42)
	c.Filtered()
	c.RevealSecrets()
	c.SetIdentityScope(bytes.Repeat([]byte("k"), 32))
	c.RegisterScope("filesystem", "production", map[string]any{"max_size": 123})
	c.Note("owned_limit", "https://user:private-password@example.invalid/source?token=private-query", true)
	var a, b bytes.Buffer
	if err := WriteWithCoverage(&a, nil, "json", false, c); err != nil {
		t.Fatal(err)
	}
	if err := WriteWithCoverage(&b, nil, "sarif", false, c); err != nil {
		t.Fatal(err)
	}
	var j, s map[string]any
	if err := json.Unmarshal(a.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	run := s["runs"].([]any)[0].(map[string]any)
	props := run["properties"].(map[string]any)
	for _, key := range []string{"schema_version", "complete", "completion_reason", "truncated", "stats", "diagnostics", "scope", "filtered", "identity_scope", "secrets_revealed"} {
		if !reflect.DeepEqual(j[key], props[key]) {
			t.Fatalf("machine envelopes disagree on %s", key)
		}
	}
	if j["schema_version"] != "1.4" || j["complete"] != false || j["filtered"] != true || j["secrets_revealed"] != true || run["invocations"].([]any)[0].(map[string]any)["executionSuccessful"] != false {
		t.Fatal("released envelope fields or execution completeness changed")
	}
	for _, hidden := range []string{"private-password", "private-query"} {
		if bytes.Contains(a.Bytes(), []byte(hidden)) || bytes.Contains(b.Bytes(), []byte(hidden)) {
			t.Fatal("coverage diagnostic exposed URL credentials")
		}
	}
}

func TestEmptyEnvelopeHasArraysAndSuccessfulExecution(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, nil, "json", false); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"scope", "diagnostics", "findings"} {
		if rows, ok := doc[key].([]any); !ok || len(rows) != 0 {
			t.Fatalf("%s is not an empty array", key)
		}
	}
	if doc["complete"] != true || doc["completion_reason"] != "completed" {
		t.Fatal("empty complete result changed meaning")
	}
}
