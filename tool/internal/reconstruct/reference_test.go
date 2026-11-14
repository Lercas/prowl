package reconstruct

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNodeReferenceParity(t *testing.T) {
	checkReference(t, "testdata/node_reference.json", 261)
}
func TestNodeTemplateReferenceParity(t *testing.T) {
	checkReference(t, "testdata/node_template_reference.json", 18)
}
func checkReference(t *testing.T, path string, expectedCount int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Rows []struct{ Code, Value string }
	}
	if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Rows) != expectedCount {
		t.Fatal("missing reference fixture")
	}
	for i, row := range fixture.Rows {
		values, limited := Extract(row.Code)
		if limited {
			t.Fatalf("reference case %d incorrectly hit a budget", i)
		}
		found := false
		for _, value := range values {
			found = found || value.Text == row.Value
		}
		if !found {
			t.Fatalf("reference case %d differs from Node.js", i)
		}
	}
}
