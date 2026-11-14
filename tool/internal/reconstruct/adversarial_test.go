package reconstruct

import "testing"

func TestEscapedStandaloneCredential(t *testing.T) {
	code := `const key="\x41KIA\u004eAFGYOEYPXU1DSYP";`
	values, _ := Extract(code)
	for _, value := range values {
		if value.Text == "AKIANAFGYOEYPXU1DSYP" {
			return
		}
	}
	t.Fatal("escaped standalone literal was missed")
}

func TestNoInventedValueFromUnsupportedJavaScriptContext(t *testing.T) {
	for name, code := range map[string]string{
		"arrow-parameter":        `const head='AKIA'; const f=(head)=>head+'NAFGYOEYPXU1DSYP';`,
		"single-arrow-parameter": `const head='AKIA'; const f=head=>head+'NAFGYOEYPXU1DSYP';`,
		"division":               `const k=unknown/'AKIA'+'NAFGYOEYPXU1DSYP';`,
		"regex":                  `const pattern=/['AKIA'+'NAFGYOEYPXU1DSYP']/;`,
		"control-regex":          `if (enabled) /['AKIA'+'NAFGYOEYPXU1DSYP']/;`,
		"tagged-template":        "const head='AKIA'; const k=tag`${head}NAFGYOEYPXU1DSYP`;",
		"escaped-dollar":         "const head='AKIA'; const k=`\\x24{head}NAFGYOEYPXU1DSYP`;",
		"escaped-brace":          "const head='AKIA'; const k=`$\\u007bhead}NAFGYOEYPXU1DSYP`;",
	} {
		t.Run(name, func(t *testing.T) {
			values, _ := Extract(code)
			for _, value := range values {
				if value.Text == "AKIANAFGYOEYPXU1DSYP" {
					t.Fatal("unsupported expression invented a credential")
				}
			}
		})
	}
}
