package verify

import (
	"crypto/sha256"
	"encoding/hex"

	"gopkg.in/yaml.v3"
)

// PolicyDigest identifies the loaded definitions, including request/extraction/
// signing and response semantics, without exporting their contents or filenames.
// Like runtime evaluation, it assumes callers do not mutate Verifiers() entries.
func (s *Set) PolicyDigest() (string, error) {
	// YAML preserves binary string contents; JSON would replace invalid UTF-8.
	data, err := yaml.Marshal(s.verifiers)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
