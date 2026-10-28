package main

import (
	"fmt"

	"github.com/Lercas/prowl/tool/internal/doctor"
	"github.com/Lercas/prowl/tool/internal/model"
)

// Load the same selected sets as scan, including partial parse/integrity errors. No requests run.
func doctorTemplateChecks(c commonFlags) []doctor.Check {
	var checks []doctor.Check
	c.coverage = model.NewCoverage()
	eng, loadErr := loadEngine(c)
	complete, _, _ := c.coverage.Snapshot()
	switch {
	case loadErr != nil || !complete || eng == nil && !c.rulesOnly:
		checks = append(checks, doctor.Check{Name: "active rule templates", Status: doctor.StatusFail, Detail: "selected set failed integrity/schema validation"})
	case eng == nil:
		checks = append(checks, doctor.Check{Name: "active rule templates", Status: doctor.StatusWarn, Detail: "rules disabled by --rules-only without --rules-dir"})
	default:
		status, detail := doctor.StatusOK, fmt.Sprintf("%d selected templates loaded", eng.Len())
		if !c.bundled && len(c.rulesDir) == 0 && !c.rulesOnly && dirExists(installedRulesDir()) {
			status, detail = doctor.StatusWarn, detail+"; installed set overrides bundled release rules (inspect version/scope)"
		}
		checks = append(checks, doctor.Check{Name: "active rule templates", Status: status, Detail: detail})
	}
	c.verify = true
	c.coverage = model.NewCoverage()
	vs, err := loadVerifySet(c)
	complete, _, _ = c.coverage.Snapshot()
	if err != nil || !complete || vs == nil {
		checks = append(checks, doctor.Check{Name: "active verifiers", Status: doctor.StatusFail, Detail: "selected set failed integrity/schema validation; no provider requests made"})
	} else {
		status, detail := doctor.StatusOK, fmt.Sprintf("%d selected verifiers loaded; no provider requests made", vs.Count())
		if !c.bundled && len(c.verifiers) == 0 && dirExists(installedVerifiersDir()) {
			status, detail = doctor.StatusWarn, detail+"; installed set overrides bundled release verifiers"
		}
		checks = append(checks, doctor.Check{Name: "active verifiers", Status: status, Detail: detail})
	}
	return checks
}
