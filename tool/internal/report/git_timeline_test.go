package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestSARIFCarriesGitTimelineWithoutPrivateGraph(t *testing.T) {
	absent := false
	f := model.Finding{Type: "owned", Path: "file.env", Redacted: "****", Git: &model.GitTimeline{Complete: true, Head: "owned-head", InHEAD: &absent}, GitRecord: &model.GitRecord{Object: model.GitObject{Blob: "PRIVATE-GRAPH"}}}
	for _, format := range []string{"json", "sarif"} {
		var b bytes.Buffer
		if err := Write(&b, []model.Finding{f}, format, false); err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(b.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		compact, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(compact, []byte(`"in_head":false`)) || !bytes.Contains(compact, []byte("owned-head")) || bytes.Contains(compact, []byte("PRIVATE-GRAPH")) {
			t.Fatal("timeline serialization or private graph boundary failed")
		}
	}
}
