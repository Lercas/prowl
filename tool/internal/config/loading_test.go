package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsAdditionalConfigDocuments(t *testing.T) {
	for _, body := range []string{"version: 1\n---\ndetectors:\n  enable: [owned]\n", "version: 1\n---\ninvalid: [\n"} {
		if cfg, err := Load(writeCfg(t, body)); err == nil || cfg != nil {
			t.Errorf("accepted hidden trailing configuration: config=%v err=%v", cfg, err)
		}
	}
}

func TestDiscoveryPreservesSelectedConfigErrors(t *testing.T) {
	for _, mode := range []string{"malformed", "match-all", "directory", "broken-link"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile(".prowl.yml", []byte("version: 1\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "malformed":
				err = os.WriteFile(".prowl.yaml", []byte("detectors: [\n"), 0o600)
			case "match-all":
				err = os.WriteFile(".prowl.yaml", []byte("detectors:\n  custom:\n    - {id: bad, regex: '.*'}\n"), 0o600)
			case "directory":
				err = os.Mkdir(".prowl.yaml", 0o700)
			case "broken-link":
				err = os.Symlink(filepath.Join(t.TempDir(), "missing"), ".prowl.yaml")
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg, err := Discover(); err == nil || cfg != nil {
				t.Errorf("%s selected config fell back: config=%v err=%v", mode, cfg, err)
			}
		})
	}
}

func TestEmptyTrailingConfigDocumentsRemainAccepted(t *testing.T) {
	if cfg, err := Load(writeCfg(t, "version: 1\n---\n# empty trailing document\n")); err != nil || cfg.Version != 1 {
		t.Fatalf("empty trailing document rejected: config=%v err=%v", cfg, err)
	}
}
