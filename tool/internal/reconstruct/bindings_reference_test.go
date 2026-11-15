package reconstruct

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestObjectBindingsNodeReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/binding_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NodeVersion string `json:"node_version"`
		Cases       []struct {
			ID     string            `json:"id"`
			Source string            `json:"source"`
			Start  int               `json:"start"`
			End    int               `json:"end"`
			Fields map[string]string `json:"fields"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) != 72 || fixture.NodeVersion == "" {
		t.Fatal("incomplete reference fixture")
	}
	for _, c := range fixture.Cases {
		t.Run(c.ID, func(t *testing.T) {
			got := ParseObjectBindings(t.Context(), c.Source).ForSpan(c.Start, c.End, c.Fields["algolia_api_key"])
			if !reflect.DeepEqual(got, c.Fields) {
				t.Fatal("static binding differs from trusted Node reference", got, c.Fields)
			}
		})
	}
}
