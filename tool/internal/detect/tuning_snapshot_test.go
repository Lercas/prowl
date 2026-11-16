package detect

import (
	"encoding/base64"
	"reflect"
	"sync"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestTuningSnapshotAllProducers(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 50000)
	legacy := newDetector(t)
	fixed := legacy.Snapshot()
	token := validGithubToken()
	fixtures := []string{
		`The secret is "Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"`,
		`api_key="Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"`,
		"password=R7fQ9wX2kL8zN4pV\npassword=P9cW6mB3qZ8xL2rT",
		`encoded="` + base64.StdEncoding.EncodeToString([]byte("token="+token)) + `"`,
		`token="` + token[:12] + `" + "` + token[12:] + `"`,
		`jwt="eyJhbGciOiJIUzI1NiJ9.` + base64.RawURLEncoding.EncodeToString([]byte(`{"password":"R7fQ9wX2kL8zN4pV"}`)) + `.c2lnbmF0dXJl"`,
	}
	before := make([][]Match, len(fixtures))
	for i, text := range fixtures {
		before[i] = fixed.Scan(text)
		if len(before[i]) == 0 {
			t.Fatalf("empty fixture %d", i)
		}
	}
	digest, err := fixed.PolicyDigest()
	if err != nil {
		t.Fatal(err)
	}
	ApplyTuning(7.5, 8, 1)
	for i, text := range fixtures {
		if got := fixed.Scan(text); !reflect.DeepEqual(got, before[i]) {
			t.Fatalf("producer %d changed after global tuning update", i)
		}
	}
	after, _ := fixed.PolicyDigest()
	if after != digest {
		t.Fatal("snapshot digest drifted")
	}
	next := legacy.Snapshot()
	changed, _ := next.PolicyDigest()
	if changed == digest {
		t.Fatal("changed thresholds retained the policy digest")
	}
	if next.MaxScanMatches() != 1 || fixed.MaxScanMatches() != 50000 {
		t.Fatal("candidate cap leaked between snapshots")
	}
	value := "sampleXk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"
	if fixed.IsExampleOrPlaceholder(value) || !next.IsExampleOrPlaceholder(value) {
		t.Fatal("placeholder threshold did not remain isolated")
	}
}

func TestExplicitTuningDoesNotInheritLegacyAndSupportsConcurrentScans(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(7.5, 8, 1)
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	fixed := NewWithTuning(tax, DefaultTuning())
	text := `The secret is "Xk9Zm2Qp7Lr4Ns8Tv1Wy6Bd3Fg5Hj0aQw"`
	want := fixed.Scan(text)
	if len(want) == 0 || fixed.Tuning() != DefaultTuning() {
		t.Fatal("explicit defaults inherited legacy settings")
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; i < 100; i++ {
			ApplyTuning(2, 2, 1)
			ApplyTuning(7.5, 8, 3)
		}
	})
	for range 4 {
		wg.Go(func() {
			for range 25 {
				if got := fixed.Scan(text); !reflect.DeepEqual(got, want) {
					t.Error("concurrent mutation changed an explicit detector")
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestPolicyDigestIncludesEveryTuningDimension(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, settings := range []Tuning{DefaultTuning(), DefaultTuning().With(2, 0, 0), DefaultTuning().With(0, 2, 0), DefaultTuning().With(0, 0, 1)} {
		digest, err := NewWithTuning(tax, settings).PolicyDigest()
		if err != nil || seen[digest] {
			t.Fatal("tuning policy collision", settings, err)
		}
		seen[digest] = true
	}
}
