package report

import "github.com/Lercas/prowl/tool/internal/model"

func addIdentityProperties(properties map[string]any, f model.Finding) {
	for key, value := range map[string]string{
		"secret_id": f.SecretID, "identity_scope": f.IdentityScope, "occurrence_id": f.OccurrenceID,
	} {
		if value != "" {
			properties[key] = value
		}
	}
	if len(f.Occurrences) > 0 {
		properties["occurrences"] = f.Occurrences
	}
	if len(f.Evidence) > 0 {
		properties["evidence"] = f.Evidence
	}
	if len(f.Provenance) > 0 {
		properties["provenance"] = f.Provenance
	}
	if f.PublicKeyAudit != nil {
		properties["public_key_audit"] = f.PublicKeyAudit
	}
	if f.Verification != nil {
		properties["verification"] = f.Verification
	}
	if f.InFinalImage != nil {
		properties["in_final_image"] = *f.InFinalImage
	}
	if f.Instruction != "" {
		properties["instruction"] = f.Instruction
	}
}
