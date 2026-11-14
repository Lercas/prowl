package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestTextEncodingViewsRecoverTypedValuesAndOriginalSpans(t *testing.T) {
	d := newDetector(t)
	encodedPercent, encodedHTML := "", ""
	for _, c := range depthAWSKey {
		encodedPercent += fmt.Sprintf("%%%02X", c)
		encodedHTML += fmt.Sprintf("&#x%02x;", c)
	}
	for _, value := range []string{encodedPercent, encodedHTML, "%41KIA" + depthAWSKey[4:], "&#65;KIA" + depthAWSKey[4:]} {
		text := "heading\napi_key = \"" + value + "\"\n"
		matches, limited := d.ScanCtxWithStatus(t.Context(), text)
		if limited {
			t.Fatal("bounded encoding unexpectedly incomplete")
		}
		m := findType(matches, "aws_access_key_id")
		if m == nil || m.Value != depthAWSKey || text[m.Start:m.End] != value {
			t.Fatalf("decoded identity or original span lost: found=%v", m != nil)
		}
	}
}

func TestTextEncodingsDoNotTurnFormattingIntoGenericCredentials(t *testing.T) {
	for _, text := range []string{"count=%02x; ratio=%99; ordinary &notAnEntity; text", `password = "Tr0ub4dor%26secret"`, "&NewLine;Password: ordinary", "p%61ssword = \"aB3xQ9zP7mK2wL5vN8tR4yC\""} {
		d := newDetector(t)
		v, limited := buildViewBudget(t.Context(), text, true, maxViewBytes, maxViewConstructs)
		if limited {
			t.Fatal("small input exhausted budget")
		}
		matches, _ := d.scanMappedView(t.Context(), text, v, true)
		for _, m := range matches {
			if m.Type == "generic_password" || m.Type == "generic_api_key" || m.Type == "generic_high_entropy" {
				t.Fatal("generic inference promoted by percent/HTML view")
			}
		}
	}
	for _, text := range []string{"%0A", "%00", "%FF", "%G1", "&#0;", "&#xD800;", "&#x110000;", "&madeup;"} {
		if _, n := textEncodingAt(text, 0); n != 0 {
			t.Fatalf("invalid/control encoding accepted: %q", text)
		}
	}
}

func TestEncodingViewsShareExistingNormalizationBudgets(t *testing.T) {
	text := strings.Repeat(`"\u0041" `, maxViewConstructs-1) + "\n" + strings.Repeat("%41", 10)
	old, oldLimited := buildViewStatus(t.Context(), text)
	if oldLimited || old == nil {
		t.Fatal("fixture did not preserve initial budget")
	}
	encoded, limited := buildViewBudget(t.Context(), text, true, maxViewBytes-len(old.text), maxViewConstructs-old.constructs)
	if !limited {
		t.Fatal("encoding discovery ignored remaining construction budget")
	}
	if encoded != nil && (len(old.text)+len(encoded.text) > maxViewBytes || old.constructs+encoded.constructs > maxViewConstructs) {
		t.Fatal("combined normalization budgets exceeded")
	}
}

func FuzzTextEncodingView(f *testing.F) {
	for _, seed := range []string{"api_key=%41KIANAFGYOEYPXU1DSYP", "token=&#65;KIANAFGYOEYPXU1DSYP", "&amp; &#xD800; %00 %GG"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 32<<10 {
			return
		}
		v, _ := buildViewBudget(t.Context(), text, true, maxViewBytes, maxViewConstructs)
		if v == nil {
			return
		}
		if len(v.text) > maxViewBytes || v.constructs > maxViewConstructs || len(v.start) != len(v.text) || len(v.end) != len(v.text) {
			t.Fatal("encoding view exceeded mapping budget")
		}
		for i := range v.start {
			if v.start[i] < 0 || v.end[i] < v.start[i] || int(v.end[i]) > len(text) {
				t.Fatal("encoding mapping outside source")
			}
		}
	})
}

func TestTextEncodingNamedEntitiesAndLiteralPlus(t *testing.T) {
	d := newDetector(t)
	github := validGithubToken()
	for _, value := range []string{strings.Replace(github, "_", "&lowbar;", 1), strings.Replace(github, "_", "%5f", 1)} {
		m := findType(d.Scan("token=\""+value+"\"\n"), "github_pat_classic")
		if m == nil || m.Value != github {
			t.Fatal("typed prefix did not survive named entity/percent encoding")
		}
	}
	secret := "wJalrXUtnFEMIK7MDENGbPxRfiCYzK8vQ2mN4pLs"
	secret = secret[:8] + "+" + secret[9:]
	value := strings.Replace(secret, "+", "%2B", 1)
	m := findType(d.Scan("aws_secret_access_key=\""+value+"\"\n"), "aws_secret_access_key")
	if m == nil || m.Value != secret {
		t.Fatal("percent-encoded plus lost the typed secret")
	}
	v, _ := buildViewBudget(t.Context(), "opaque=%41+B", true, maxViewBytes, maxViewConstructs)
	if v == nil || !strings.Contains(v.text, "opaque=A+B") {
		t.Fatal("literal plus was treated as form whitespace")
	}
	matches := d.Scan("hint=%20; **Password:** Tr0ub4dor&3xKq9\n")
	found := false
	for _, m := range matches {
		found = found || m.Type == "generic_password" && m.Value == "Tr0ub4dor&3xKq9"
	}
	if !found {
		t.Fatal("an unrelated encoding suppressed legacy markup normalization")
	}
}
