package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func policyConfig(t *testing.T, text string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-config-filename.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func snapshotConfig(t *testing.T, c *Config) *Policy {
	t.Helper()
	p, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestConfigPolicySnapshotSurvivesMutableOriginal(t *testing.T) {
	c := policyConfig(t, "allowlist:\n values: [owned-value]\n paths: [vendor/]\n regexes: ['owned_[0-9]{4}']\n stopwords: [owned-stopword]\n")
	c.MergeAllowlist([]string{"merged_[0-9]{4}"}, []string{"generated/"}, []string{"merged-stopword"})
	snapshot := snapshotConfig(t, c)
	id := snapshot.PolicyID()
	if len(id) != 64 || !snapshot.Restrictive() {
		t.Fatal("lost policy identity or suppression metadata")
	}
	for _, tc := range [][2]string{{"owned-value", "src/a"}, {"x", "vendor/a"}, {"owned_1234", "src/a"}, {"has-owned-stopword", "src/a"}, {"merged_1234", "src/a"}, {"x", "generated/a"}, {"has-merged-stopword", "src/a"}} {
		if !snapshot.Allowed(tc[0], tc[1]) {
			t.Fatal("lost effective allowlist", tc)
		}
	}
	c.Allowlist.Values[0] = "different"
	c.allowVal["owned-value"] = false
	c.allowVal["new-value"] = true
	c.allowPaths[0] = "elsewhere/"
	c.allowStopWords[0] = "other"
	c.allowRe = nil
	c.MergeAllowlist([]string{"new_[0-9]{4}"}, []string{"new/"}, []string{"new-stopword"})
	if !snapshot.Allowed("owned-value", "src/a") || snapshot.Allowed("new-value", "src/a") || snapshot.Allowed("new_1234", "src/a") || snapshot.PolicyID() != id {
		t.Fatal("mutable config changed frozen allowlist")
	}
	if snapshotConfig(t, c).PolicyID() == id {
		t.Fatal("fresh snapshot missed changed declared/effective policy")
	}
}
func TestConfigPolicySeparatesDeclaredAndEffectiveState(t *testing.T) {
	loaded := policyConfig(t, "allowlist: {values: [owned-value]}\n")
	declared := &Config{}
	declared.Allowlist.Values = []string{"owned-value"}
	a, b := snapshotConfig(t, loaded), snapshotConfig(t, declared)
	if !a.Allowed("owned-value", "src/a") || b.Allowed("owned-value", "src/a") || a.PolicyID() == b.PolicyID() {
		t.Fatal("uncompiled declaration borrowed active policy")
	}
	same := policyConfig(t, "# presentation only\nallowlist: {values: [owned-value]}\n")
	if a.PolicyID() != snapshotConfig(t, same).PolicyID() {
		t.Fatal("filename/comments became configuration identity")
	}
	first := policyConfig(t, "allowlist: {values: [!!binary /w==]}\n")
	second := policyConfig(t, "allowlist: {values: [!!binary /g==]}\n")
	if snapshotConfig(t, first).PolicyID() == snapshotConfig(t, second).PolicyID() {
		t.Fatal("binary string identity was lossy")
	}
}
func TestConfigPolicyBoundsAndDefaults(t *testing.T) {
	c := &Config{}
	p := snapshotConfig(t, c)
	if p.Restrictive() || p.Allowed("x", "src/a") {
		t.Fatal("empty config suppresses input")
	}
	c.Allowlist.Values = make([]string, maxPolicyEntries+1)
	if _, err := c.Snapshot(); err == nil {
		t.Fatal("entry budget bypassed")
	}
	c = &Config{}
	c.Exclude = []string{strings.Repeat("x", maxPolicyBytes+1)}
	if _, err := c.Snapshot(); err == nil {
		t.Fatal("input byte budget bypassed")
	}
	for _, c := range []*Config{policyConfig(t, "detectors: {disable: [unrelated]}\n"), policyConfig(t, "detectors: {enable: [aws_access_key_id]}\n"), policyConfig(t, "allowlist: {regexes: ['.*']}\n")} {
		if !snapshotConfig(t, c).Restrictive() {
			t.Fatal("declared suppression lost released filtered guard")
		}
	}
}
