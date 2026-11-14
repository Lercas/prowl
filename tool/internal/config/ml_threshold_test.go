package config

import (
	"math"
	"strings"
	"testing"
)

func TestInvalidMLThresholdRejectedAtLoad(t *testing.T) {
	for _, value := range []string{".nan", ".inf", "-.inf", "-0.01", "1.01"} {
		t.Run(value, func(t *testing.T) {
			if cfg, err := Load(writeCfg(t, "performance:\n  ml_threshold: "+value+"\n")); err == nil || cfg != nil || !strings.Contains(err.Error(), "performance.ml_threshold") {
				t.Fatalf("invalid ML threshold accepted: cfg=%v err=%v", cfg, err)
			}
		})
	}
}

func TestMLThresholdValidationForConstructedConfig(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -0.01, 1.01} {
		cfg := &Config{}
		cfg.Performance.MLThreshold = value
		if issues := cfg.Validate(); len(issues) != 1 || !strings.Contains(issues[0], "performance.ml_threshold") {
			t.Fatalf("validator accepted invalid threshold %v: %v", value, issues)
		}
	}
	for _, value := range []string{"0", "-0.0", "0.2", "1"} {
		cfg, err := Load(writeCfg(t, "performance:\n  ml_threshold: "+value+"\n"))
		if err != nil || len(cfg.Validate()) != 0 {
			t.Fatalf("valid threshold %s rejected: cfg=%v err=%v", value, cfg, err)
		}
	}
}
