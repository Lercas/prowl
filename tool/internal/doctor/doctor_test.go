package doctor

import (
	"testing"

	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestRunHealthy(t *testing.T) {
	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	checks := Run(detect.New(tax), tax, nil)
	if !Healthy(checks) {
		for _, c := range checks {
			if c.Status == StatusFail {
				t.Errorf("unexpected failing check: %s — %s", c.Name, c.Detail)
			}
		}
	}
	// the detection self-test must report OK (proves the engine end-to-end, incl. github checksum)
	var sawDetect, sawChecksum bool
	for _, c := range checks {
		if c.Name == "detection self-test" {
			sawDetect = true
			if c.Status != StatusOK {
				t.Errorf("detection self-test not OK: %s", c.Detail)
			}
		}
		if c.Name == "checksum validators" && c.Status != StatusOK {
			t.Errorf("checksum validators not OK: %s", c.Detail)
		}
		if c.Name == "checksum validators" {
			sawChecksum = true
		}
	}
	if !sawDetect || !sawChecksum {
		t.Error("expected detection + checksum checks to be present")
	}
}

func TestHealthyLogic(t *testing.T) {
	if !Healthy([]Check{{Status: StatusOK}, {Status: StatusWarn}}) {
		t.Error("warnings should not make it unhealthy")
	}
	if Healthy([]Check{{Status: StatusOK}, {Status: StatusFail}}) {
		t.Error("a failure must make it unhealthy")
	}
}

func TestConfigChecksCatchBadRegex(t *testing.T) {
	cfg := &config.Config{}
	cfg.Detectors.Custom = []config.CustomRule{{ID: "broken", Regex: "([unterminated"}}
	checks := configChecks(cfg)
	if len(checks) != 1 || checks[0].Status != StatusFail {
		t.Errorf("expected a failing config check for the bad regex, got %+v", checks)
	}
}
