package main

import (
	"github.com/Lercas/prowl/tool/internal/config"
	"github.com/Lercas/prowl/tool/internal/detect"
	"testing"
)

func TestLoadDetectorUsesOnlySelectedTuning(t *testing.T) {
	defer detect.ApplyTuning(3.5, 4.2, 50000)
	detect.ApplyTuning(7.5, 8, 1)
	cfg := &config.Config{}
	cfg.Detection.GenericEntropyMin = 2
	cfg.Detection.PlaceholderMaxEntropy = 3
	cfg.Detection.MaxMatchesPerFile = 17
	selected, _, err := loadDetector(commonFlags{bundled: true}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defaults, _, err := loadDetector(commonFlags{bundled: true}, &config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Detection.GenericEntropyMin = 7
	detect.ApplyTuning(6, 6, 2)
	if selected.Tuning() != detect.DefaultTuning().With(2, 3, 17) || defaults.Tuning() != detect.DefaultTuning() {
		t.Fatal("detector settings inherited or retained mutable caller state")
	}
}
