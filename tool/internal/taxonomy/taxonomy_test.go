package taxonomy

import "testing"

func TestLoadDefault(t *testing.T) {
	tax, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	if len(tax.Types) < 25 {
		t.Errorf("expected >=25 compiled types, got %d (skipped %d)", len(tax.Types), len(tax.Skipped))
	}
	seen := map[string]bool{}
	for _, st := range tax.Types {
		if st.ID == "" {
			t.Error("type with empty id")
		}
		if st.RE == nil {
			t.Errorf("type %s has nil compiled regex", st.ID)
		}
		if seen[st.ID] {
			t.Errorf("duplicate type id %s", st.ID)
		}
		seen[st.ID] = true
	}
	for _, want := range []string{"aws_access_key_id", "github_pat_classic", "private_key_pem", "jwt"} {
		if !seen[want] {
			t.Errorf("missing core type %s", want)
		}
	}
}

func TestGenericLast(t *testing.T) {
	if !GenericLast["generic_high_entropy"] || GenericLast["aws_access_key_id"] {
		t.Error("GenericLast classification wrong")
	}
}
