package secretindex

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lercas/prowl/tool/internal/model"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "index")
	s, err := Open(t.Context(), directory, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, directory
}

func observed(id *Identity, raw, source, path string, verified *bool) model.Finding {
	return model.Finding{Type: "owned", Source: source, Path: path, Line: 3, Col: 9, ValueFingerprint: id.Fingerprint(raw), IndexLocationID: id.Location(source, path, 3, 9), IndexType: "owned", IndexSource: source, IndexPath: path, Verified: verified,
		Redacted: raw, Context: &model.FindingContext{Line: raw}, URL: "https://host/?secret=" + raw, Rationale: raw}
}

func boolPointer(value bool) *bool { return &value }

func recordTest(t *testing.T, s *Store, scope string, at time.Time, complete bool, findings ...model.Finding) int64 {
	t.Helper()
	id, err := s.Record(t.Context(), scope, at, complete, findings)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIndexLinksSourcesWithoutPersistingRawValues(t *testing.T) {
	s, directory := openTestStore(t)
	id := s.Identity()
	raw := "Owned_Secret_Z7mV8qR3pL9sK2tN6wX4"
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	first := observed(id, raw, "code", "repository/prod.env", boolPointer(true))
	second := observed(id, raw, "jira", "APP-7", nil)
	scanID := recordTest(t, s, "customer", at, true, first, first, second)
	secrets, err := s.Secrets(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].LocationCount != 2 || secrets[0].LastConfirmedState != "live" || secrets[0].ValueID != id.Fingerprint(raw) {
		t.Fatalf("cross-source identity lost: %+v", secrets)
	}
	if id.Fingerprint(raw) == id.Fingerprint(raw+"x") || id.Fingerprint("") != "" {
		t.Fatal("invalid value identity")
	}
	_, directory2 := openTestStore(t)
	other, err := LoadIdentity(directory2, false)
	if err != nil {
		t.Fatal(err)
	}
	if id.Fingerprint(raw) == other.Fingerprint(raw) {
		t.Fatal("indexes reused a global or unkeyed identity")
	}
	for _, name := range []string{"key", "index.sqlite", "index.sqlite-journal", "index.sqlite-wal", "index.sqlite-shm"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(raw)) {
			t.Fatalf("%s contains a raw value, report context, or rationale", name)
		}
	}
	readOnly, err := Open(t.Context(), directory, true)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if _, err := readOnly.Record(t.Context(), "customer", at, true, nil); err == nil {
		t.Fatal("read-only index accepted a write")
	}
	scans, err := readOnly.Scans(t.Context(), "customer")
	if err != nil || len(scans) != 1 || scans[0].ID != scanID || !scans[0].Complete {
		t.Fatal("persisted scan did not survive reopen")
	}
}

func TestIndexDiffAndProviderTransitions(t *testing.T) {
	s, _ := openTestStore(t)
	identity := s.Identity()
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	old := observed(identity, "Old_Value_7mN8pQ9rS2tU3vW4", "code", "old.env", boolPointer(true))
	a := recordTest(t, s, "production", at, true, old)
	unknown := old
	unknown.Verified = nil
	partialDead := old
	partialDead.Verified = boolPointer(false)
	partial := recordTest(t, s, "production", at.Add(time.Hour), false, partialDead)
	if _, err := s.Diff(t.Context(), a, partial); err == nil {
		t.Fatal("partial scan was used as absence evidence")
	}
	secrets, err := s.Secrets(t.Context(), "production")
	if err != nil || secrets[0].LastConfirmedState != "live" || len(secrets[0].Transitions) != 0 {
		t.Fatal("partial observation certified revocation")
	}
	b := recordTest(t, s, "production", at.Add(90*time.Minute), true, unknown)
	if diff, err := s.Diff(t.Context(), a, b); err != nil || len(diff.VerificationChanges) != 0 {
		t.Fatal("unknown verification became a state transition")
	}
	dead := old
	dead.Verified = boolPointer(false)
	newKey := observed(identity, "New_Value_7mN8pQ9rS2tU3vW4", "jira", "APP-8", nil)
	c := recordTest(t, s, "production", at.Add(2*time.Hour), true, dead, newKey)
	diff, err := s.Diff(t.Context(), a, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.NewValues) != 1 || diff.NewValues[0] != newKey.ValueFingerprint || len(diff.VerificationChanges) != 1 || diff.VerificationChanges[0].From != "live" || diff.VerificationChanges[0].To != "dead" {
		t.Fatalf("unexpected diff: %+v", diff)
	}
	secrets, err = s.Secrets(t.Context(), "production")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if secret.ValueID == old.ValueFingerprint {
			if secret.LastConfirmedState != "dead" || len(secret.Transitions) != 1 || secret.Transitions[0].SecondsSinceFirstLive == nil || *secret.Transitions[0].SecondsSinceFirstLive != 7200 {
				t.Fatal("observed remediation interval was not preserved")
			}
		}
	}
	d := recordTest(t, s, "production", at.Add(3*time.Hour), true, newKey)
	diff, err = s.Diff(t.Context(), c, d)
	if err != nil || len(diff.NotSeenValues) != 1 || diff.NotSeenValues[0] != old.ValueFingerprint || len(diff.VerificationChanges) != 0 {
		t.Fatal("disappearance was confused with revocation")
	}
	other := recordTest(t, s, "another-scope", at.Add(4*time.Hour), true, newKey)
	if _, err := s.Diff(t.Context(), d, other); err == nil {
		t.Fatal("different scopes compared")
	}
	if _, err := s.Diff(t.Context(), d, c); err == nil {
		t.Fatal("reversed diff accepted")
	}
}

func TestIndexConclusiveVerdictAggregation(t *testing.T) {
	s, _ := openTestStore(t)
	id := s.Identity()
	at := time.Now().UTC()
	a := observed(id, "Value_7mN8pQ9rS2tU3vW4", "code", "one.env", boolPointer(false))
	b := observed(id, "Value_7mN8pQ9rS2tU3vW4", "jira", "APP-9", nil)
	recordTest(t, s, "scope", at, true, a, b)
	secrets, err := s.Secrets(t.Context(), "")
	if err != nil || secrets[0].LastConfirmedState != "unknown" {
		t.Fatal("mixed dead/unknown evidence became confirmed dead")
	}
	b.Verified = boolPointer(true)
	recordTest(t, s, "scope", at.Add(time.Hour), true, a, b)
	secrets, err = s.Secrets(t.Context(), "")
	if err != nil || secrets[0].LastConfirmedState != "live" {
		t.Fatal("live evidence did not take precedence")
	}
}

func TestIndexRejectsMissingOrForeignIdentityWithoutPartialWrites(t *testing.T) {
	s, _ := openTestStore(t)
	other, _ := openTestStore(t)
	good := observed(s.Identity(), "Owned_Value_3aB7dE9fG2hK5", "code", "good.env", nil)
	bad := observed(other.Identity(), "Owned_Value_3aB7dE9fG2hK5", "code", "foreign.env", nil)
	for _, findings := range [][]model.Finding{{good, bad}, {{Type: "owned"}}} {
		if _, err := s.Record(t.Context(), "scope", time.Now(), true, findings); err == nil {
			t.Fatal("unbound finding accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.Record(ctx, "scope", time.Now(), true, []model.Finding{good}); err == nil {
		t.Fatal("cancelled transaction committed")
	}
	scans, err := s.Scans(t.Context(), "")
	if err != nil || len(scans) != 0 {
		t.Fatal("invalid/cancelled input left a partial snapshot")
	}
	partial := recordTest(t, s, "scope", time.Now(), true, good, model.Finding{Type: "results_truncated"})
	scans, err = s.Scans(t.Context(), "")
	if err != nil || len(scans) != 1 || scans[0].Complete || scans[0].ID != partial {
		t.Fatal("incomplete diagnostic lost at storage boundary")
	}
}

func TestIdentityFilesFailClosed(t *testing.T) {
	_, directory := openTestStore(t)
	before, err := os.ReadFile(filepath.Join(directory, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(directory, "key"))
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(directory, "key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(t.Context(), directory, true); err == nil {
		opened.Close()
		t.Fatal("replacement key silently rebound a database")
	}
	after, err := os.ReadFile(filepath.Join(directory, "index.sqlite"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only key mismatch changed database")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if opened, err := Open(t.Context(), missing, true); err == nil {
		opened.Close()
		t.Fatal("read-only inspection created an index")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("read-only inspection created filesystem content")
	}
	if runtime.GOOS != "windows" {
		unsafe := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(unsafe, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIdentity(unsafe, true); err == nil {
			t.Fatal("world-readable index directory accepted")
		}
	}
}

func TestConcurrentIndexTransactionsAndDeterministicReports(t *testing.T) {
	s, _ := openTestStore(t)
	f := observed(s.Identity(), "Concurrent_Value_7mN8pQ9rS2tU3vW4", "code", "app.env", nil)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Record(t.Context(), "scope", time.Now(), true, []model.Finding{f})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	scans, err := s.Scans(t.Context(), "")
	if err != nil || len(scans) != 12 {
		t.Fatal("concurrent transactions were lost")
	}
	a, err := s.Secrets(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Secrets(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	if !bytes.Equal(left, right) || len(a) != 1 || a[0].LocationCount != 1 {
		t.Fatal("report is not deterministic or duplicate sightings inflated location count")
	}
	if strings.Contains(string(left), "Concurrent_Value") {
		t.Fatal("index report contains raw value")
	}
}

func TestIndexStateRefusesSymlinksAndHardlinkAliases(t *testing.T) {
	for _, name := range []string{"key", "index.sqlite"} {
		t.Run(name, func(t *testing.T) {
			_, dir := openTestStore(t)
			path := filepath.Join(dir, name)
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Link(path, alias); err != nil {
				t.Skip("hard links unavailable")
			}
			if opened, err := Open(t.Context(), dir, true); err == nil {
				opened.Close()
				t.Fatal("hard-linked state file accepted")
			}
		})
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlink unavailable")
	}
	if _, err := LoadIdentity(link, true); err == nil {
		t.Fatal("state directory symlink accepted")
	}
}

func TestIndexSummaryCanBeReadAsOfAnEarlierImmutableSnapshot(t *testing.T) {
	s, _ := openTestStore(t)
	at := time.Now().UTC()
	a := observed(s.Identity(), "First_Value_7mN8pQ9rS2tU3vW4", "code", "one.env", nil)
	id := recordTest(t, s, "scope", at, true, a)
	b := observed(s.Identity(), "Second_Value_7mN8pQ9rS2tU3vW4", "jira", "APP-9", nil)
	recordTest(t, s, "scope", at.Add(time.Hour), true, b)
	old, err := s.SecretsThrough(t.Context(), "scope", id)
	if err != nil || len(old) != 1 || old[0].ValueID != a.ValueFingerprint {
		t.Fatal("later transaction changed an earlier snapshot view")
	}
}

func TestIndexSeparatesRelativeLocationsFromDifferentScopes(t *testing.T) {
	s, _ := openTestStore(t)
	f := observed(s.Identity(), "Value_7mN8pQ9rS2tU3vW4", "code", "app.env", nil)
	recordTest(t, s, "repo:a", time.Now(), true, f)
	recordTest(t, s, "repo:b", time.Now(), true, f)
	secrets, err := s.Secrets(t.Context(), "")
	if err != nil || len(secrets) != 1 || secrets[0].LocationCount != 2 {
		t.Fatal("different repository scopes collapsed a relative location")
	}
	if secrets[0].Locations[0].Scope == secrets[0].Locations[1].Scope {
		t.Fatal("location report lost scope provenance")
	}
}
