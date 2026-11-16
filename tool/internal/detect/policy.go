package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

// PolicyDigest describes the active taxonomy without exposing its patterns in reports.
func (d *Detector) PolicyDigest() (string, error) {
	types := make([]taxonomy.SecretType, 0, len(d.types))
	for _, compiled := range d.types {
		st := compiled.st
		st.RE = nil
		types = append(types, st)
	}
	var snapshot any = types
	if settings := d.Tuning(); settings != DefaultTuning() {
		snapshot = struct {
			Types  []taxonomy.SecretType
			Tuning Tuning
		}{types, settings}
	}
	b, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
