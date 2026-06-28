package main

import (
	"strings"
	"testing"
)

func TestMCPArgv(t *testing.T) {
	argv, err := mcpArgv("prowl_scan", map[string]any{"path": "/x", "verify": true, "ml": true})
	if err != nil || strings.Join(argv, " ") != "scan /x --verify --ml --format json" {
		t.Errorf("scan argv = %v, err=%v", argv, err)
	}
	// domain MUST refuse without an authorized attestation
	if _, err := mcpArgv("prowl_domain", map[string]any{"target": "x", "authorized": false}); err == nil {
		t.Error("domain without authorized must error")
	}
	argv, err = mcpArgv("prowl_domain", map[string]any{"target": "x", "authorized": true, "recon": true})
	if err != nil || strings.Join(argv, " ") != "domain x --authorized --recon --format json" {
		t.Errorf("domain argv = %v, err=%v", argv, err)
	}
	if _, err := mcpArgv("prowl_scan", map[string]any{}); err == nil {
		t.Error("missing path must error")
	}
	// a dash-led positional would be reparsed as a prowl flag (e.g. --show-secrets) — must be rejected
	if _, err := mcpArgv("prowl_scan", map[string]any{"path": "--show-secrets"}); err == nil {
		t.Error("dash-led path must error")
	}
	if _, err := mcpArgv("prowl_domain", map[string]any{"target": "-rf", "authorized": true}); err == nil {
		t.Error("dash-led target must error")
	}
	if _, err := mcpArgv("nope", map[string]any{}); err == nil {
		t.Error("unknown tool must error")
	}
}
