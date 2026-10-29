package detect

import (
	"context"
	"encoding/base64"
	"reflect"
	"regexp"
	"testing"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestScanCapStatusSurvivesFilteringAndOverlap(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	for _, tc := range []struct {
		name string
		tax  *taxonomy.Taxonomy
		text string
		want int
	}{
		{"overlap", &taxonomy.Taxonomy{Types: []taxonomy.SecretType{
			{ID: "owned_first", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
			{ID: "owned_overlap", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
		}}, "OWNED_G7hJ9kL2mN5p", 1},
		{"filtered-extraction", &taxonomy.Taxonomy{Types: []taxonomy.SecretType{
			{ID: "owned_filtered", Category: "cloud", RE: regexp.MustCompile(`example|OWNED_[A-Za-z0-9]{12}`)},
		}}, "example example example example OWNED_G7hJ9kL2mN5p", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := New(tc.tax)
			matches, limited := d.ScanCtxWithStatus(context.Background(), tc.text)
			if !limited || len(matches) != tc.want {
				t.Fatalf("raw cap hidden: limited=%v matches=%d", limited, len(matches))
			}
			if !reflect.DeepEqual(matches, d.Scan(tc.text)) {
				t.Fatal("status reporting changed legacy detector matches")
			}
		})
	}
}

func TestDecodedCandidateCapStatus(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 2)
	tax := &taxonomy.Taxonomy{Types: []taxonomy.SecretType{
		{ID: "owned_filtered", Category: "cloud", RE: regexp.MustCompile(`example|OWNED_[A-Za-z0-9]{12}`)},
	}}
	d := New(tax)
	encoded := base64.StdEncoding.EncodeToString([]byte("example example example example OWNED_G7hJ9kL2mN5p"))
	matches, limited := d.unmaskBase64Candidates(context.Background(), []Match{{Value: encoded}})
	if !limited || len(matches) != 0 {
		t.Fatal("bounded decoded extraction was reported as complete")
	}
}

func TestNormalScanCapStatusIsComplete(t *testing.T) {
	defer ApplyTuning(3.5, 4.2, 50000)
	ApplyTuning(3.5, 4.2, 10)
	tax := &taxonomy.Taxonomy{Types: []taxonomy.SecretType{
		{ID: "owned_normal", Category: "cloud", RE: regexp.MustCompile(`OWNED_[A-Za-z0-9]{12}`)},
	}}
	d := New(tax)
	for _, text := range []string{"", "clean text", "OWNED_G7hJ9kL2mN5p"} {
		matches, limited := d.ScanCtxWithStatus(context.Background(), text)
		if limited || !reflect.DeepEqual(matches, d.Scan(text)) {
			t.Fatal("normal scan changed or was marked incomplete")
		}
	}
}
