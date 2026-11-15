package scan

// A known companion with a non-string value must not disappear and let another
// alias silently supply the resource identity. These markers are captured only
// for an explicitly configured public auditor, independently of legacy verify/ML.
func (doc *literalDocument) markPublicUnknown(group int, name string) {
	if name == "" {
		return
	}
	if doc.publicUnknown == nil {
		doc.publicUnknown = map[int]map[string]bool{}
	}
	if doc.publicUnknown[group] == nil {
		doc.publicUnknown[group] = map[string]bool{}
	}
	doc.publicUnknown[group][name] = true
}

func (doc *literalDocument) publicBindingsFor(group int, fields map[string]string) map[string]string {
	unknown := doc.publicUnknown[group]
	if len(unknown) == 0 {
		return fields
	}
	result := make(map[string]string, len(fields)+len(unknown))
	for name, value := range fields {
		result[name] = value
	}
	for name := range unknown {
		result[name] = ""
	}
	return result
}
