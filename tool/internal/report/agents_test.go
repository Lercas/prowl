package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestAgentProvenanceIsOptionalAndPreservedInSARIF(t *testing.T) {
	f := model.Finding{Type: "owned", Path: "chat.jsonl", Agent: &model.AgentProvenance{Product: "claude", Kind: "transcript"}, Redacted: "****"}
	for _, format := range []string{"json", "sarif"} {
		var b bytes.Buffer
		if err := Write(&b, []model.Finding{f}, format, false); err != nil {
			t.Fatal(err)
		}
		var parsed any
		if err := json.Unmarshal(b.Bytes(), &parsed); err != nil {
			t.Fatal(err)
		}
		compact, err := json.Marshal(parsed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(compact, []byte(`"agent":{"kind":"transcript","product":"claude"}`)) {
			t.Fatal("agent provenance lost")
		}
		f.Agent = nil
		b.Reset()
		if err := Write(&b, []model.Finding{f}, format, false); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b.Bytes(), []byte(`"agent"`)) {
			t.Fatal("agent metadata enabled for ordinary scan")
		}
		f.Agent = &model.AgentProvenance{Product: "claude", Kind: "transcript"}
	}
}
