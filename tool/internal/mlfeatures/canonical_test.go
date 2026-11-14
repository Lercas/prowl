package mlfeatures

import "testing"

func TestParserContextAppendsFlagsWithoutChangingOriginalFeatures(t *testing.T) {
	plain := Extract("Quartz19!Mango", Context{Name: "password", Source: "code"})
	proved := Extract("Quartz19!Mango", Context{Name: "password", Source: "code", ParserLiteralSensitive: true, UINamespace: true})
	for i := 0; i < 49; i++ {
		if plain[i] != proved[i] {
			t.Fatal("parser proof changed an original feature")
		}
	}
	if plain[49] != 0 || plain[50] != 0 || proved[49] != 1 || proved[50] != 1 {
		t.Fatal("parser context flags are not explicit booleans")
	}
}
