package reconstruct

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestStringOrderNodeReference(t *testing.T) {
	data, err := os.ReadFile("testdata/string_order_reference.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NodeVersion string `json:"node_version"`
		Rows        []struct {
			Code, Value string
			Start, End  int
			WellFormed  bool `json:"well_formed"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Rows) != 288 || fixture.NodeVersion == "" {
		t.Fatal("missing Node fixture", err)
	}
	for i, row := range fixture.Rows {
		values, limited := Extract(row.Code)
		if !row.WellFormed {
			if !limited {
				t.Fatal("malformed UTF-16 did not preserve incompleteness", i)
			}
			for _, v := range values {
				if v.Expression.Start == row.Start && v.Expression.End == row.End {
					t.Fatal("malformed value emitted", i)
				}
			}
			continue
		}
		if limited {
			t.Fatal("reference exceeded budget", i)
		}
		found := false
		for _, v := range values {
			if v.Expression.Start == row.Start && v.Expression.End == row.End && v.Text == row.Value {
				found = true
			}
		}
		if !found {
			t.Fatal("Node disagreement", i, row.Code)
		}
	}
}

func TestStringOrderRejectsUnknownCalls(t *testing.T) {
	const reversed = "PYSD1UXPYE OYGFANAIKA"
	for _, expression := range []string{
		`unknown.split("").reverse().join("")`,
		`"` + reversed + `".split(separator).reverse().join("")`,
		`"` + reversed + `".split("").reverse().join(joiner)`,
		`"` + reversed + `".split("").reverse(callback).join("")`,
		`"` + reversed + `".split("").sort().join("")`,
		`"` + reversed + `".split(/ /).reverse().join("")`,
		`"` + reversed + `".split("",limit).reverse().join("")`,
		`"` + reversed + `"["split"]("").reverse().join("")`,
		`"` + reversed + `".split("").reverse().join("",unknown)`,
		`"` + reversed + `".split().reverse().join("")`,
		`"` + reversed + `".split("").reverse().join()`,
	} {
		values, _ := Extract("const key=" + expression + ";")
		for _, v := range values {
			if strings.Contains(v.Transform, "constant-string-split") {
				t.Fatal("unknown operation reconstructed", expression)
			}
		}
	}
	// A separator whose declaration is mutable or shadowed remains unknown.
	for _, code := range []string{
		`let separator="";const key="PYSD1UXPYEOYGFANAIKA".split(separator).reverse().join("");`,
		`const separator="";separator=unknown;const key="PYSD1UXPYEOYGFANAIKA".split(separator).reverse().join("");`,
		`const separator="";const f=separator=>"PYSD1UXPYEOYGFANAIKA".split(separator).reverse().join("");`,
	} {
		values, _ := Extract(code)
		for _, v := range values {
			if strings.Contains(v.Transform, "constant-string-split") {
				t.Fatal("borrowed separator binding", code)
			}
		}
	}
}

func TestStringOrderBudgetsAndUTF16(t *testing.T) {
	for _, expression := range []string{
		`"` + strings.Repeat("a", maxSplitParts+1) + `".split("").join("")`,
		`"` + strings.Repeat("a ", maxSplitParts) + `".split(" ").join("")`,
		`"` + strings.Repeat("a", 100) + `".split("").join("` + strings.Repeat("b", 1000) + `")`,
		`"prefix😀suffix".split("").reverse().join("")`,
		`"prefix😀suffix".split("").join(" ")`,
	} {
		values, limited := Extract("const key=" + expression + ";")
		if !limited {
			t.Fatal("missing limit or malformed-UTF16 marker")
		}
		for _, v := range values {
			if strings.Contains(v.Transform, "constant-string-split") {
				t.Fatal("invalid value escaped")
			}
		}
	}
	// Empty split must preserve the two surrogate halves until the final join.
	got, ok := splitStringUnits("😀", "")
	if !ok || len(got) != 2 || got[0][0] != 0xd83d || got[1][0] != 0xde00 {
		t.Fatal("split used code points")
	}
	if text, ok := joinStringUnits(got, ""); !ok || text != "😀" {
		t.Fatal("valid pair lost")
	}
	if text, ok := joinStringUnits([][]uint16{{0xde00}, {0xd83d}}, ""); ok || text != "" {
		t.Fatal("invalid pair replaced")
	}
}

func TestStringOrderPrototypeAccessIsNotInterpreted(t *testing.T) {
	for _, prefix := range []string{`String.prototype.split=unknown;`, `Array.prototype.reverse=unknown;`, `Array["prototype"]["join"]=unknown;`, `const p=String.prototype;`} {
		values, limited := Extract(prefix + `const key="PYSD1UXPYEOYGFANAIKA".split("").reverse().join("");`)
		if !limited {
			t.Fatal("prototype uncertainty lost")
		}
		for _, v := range values {
			if strings.Contains(v.Transform, "constant-string-split") {
				t.Fatal("prototype override interpreted")
			}
		}
	}
}
func TestStringOrderTransformAndPartBoundaries(t *testing.T) {
	code := `const key="abcdefghijklmnop"` + strings.Repeat(`.split("").join("")`, 40) + `;`
	if _, limited := Extract(code); !limited {
		t.Fatal("method chains escaped transform budget")
	}
	for _, text := range []string{strings.Repeat("a", maxSplitParts), strings.Repeat("a|", maxSplitParts-1) + "a"} {
		separator := ""
		if strings.Contains(text, "|") {
			separator = "|"
		}
		code := `const key="` + text + `".split("` + separator + `").join("");`
		values, limited := Extract(code)
		if limited || len(values) != 1 || len(values[0].Text) != maxSplitParts {
			t.Fatal("exact part bound rejected")
		}
	}
}
