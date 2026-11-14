package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/mlfeatures"
)

func TestRunCanonicalFeatures(t *testing.T) {
	var out bytes.Buffer
	if err := run(strings.NewReader(`{"value":"synthetic","context":{"name":"token","source":"code"}}`), &out, false); err != nil {
		t.Fatal(err)
	}
	var features []float64
	if err := json.Unmarshal(out.Bytes(), &features); err != nil {
		t.Fatal(err)
	}
	if len(features) != len(mlfeatures.FeatureNames) || features[31] != 1 {
		t.Fatal("missing canonical features or record context")
	}
	if strings.Contains(out.String(), "synthetic") {
		t.Fatal("feature output leaked a raw value")
	}
}

func TestRunInvalidRecordDoesNotEchoValues(t *testing.T) {
	var out bytes.Buffer
	err := run(strings.NewReader(`{"value":"sensitive-value",BROKEN}`), &out, false)
	if err == nil || strings.Contains(err.Error(), "sensitive-value") || out.Len() != 0 {
		t.Fatal("invalid input did not fail without exposing its value")
	}
}
