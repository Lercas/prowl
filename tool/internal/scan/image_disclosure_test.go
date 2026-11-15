package scan

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/model"
)

func TestImageInstructionUsesExplicitSourceDisclosure(t *testing.T) {
	const other = "AKIA4MNQ2RST7UVWX9YZ"
	for _, reveal := range []bool{false, true} {
		it := model.Item{Text: "AWS=" + encScanSecret, Source: "code", Path: "image|layer0:prod.env", Meta: map[string]any{"instruction": "RUN export SECONDARY=" + other}}
		fs := New(Options{Detector: detector(t), RevealSecrets: reveal}).Findings(t.Context(), it)
		if len(fs) != 1 {
			t.Fatal("fixture did not produce one typed finding")
		}
		raw, err := json.Marshal(fs)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), other) != reveal || (fs[0].Instruction != "") != reveal {
			t.Fatal("image instruction leaked source context or ignored explicit disclosure")
		}
	}
}
