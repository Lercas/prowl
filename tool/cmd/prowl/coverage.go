package main

import "github.com/Lercas/prowl/tool/internal/model"

func containsIncomplete(fs []model.Finding) bool {
	for _, f := range fs {
		if model.IsIncompleteFinding(f) {
			return true
		}
	}
	return false
}

func keepVerifiedWithCoverage(c commonFlags, fs []model.Finding) []model.Finding {
	kept := keepVerified(fs)
	if len(kept) < len(fs) {
		c.coverage.Filtered()
	}
	return kept
}

func capWithCoverage(c commonFlags, fs []model.Finding) []model.Finding {
	kept := capGenericPerFile(fs, c.maxPerFile)
	if len(kept) < len(fs) {
		c.coverage.Filtered()
	}
	return kept
}
