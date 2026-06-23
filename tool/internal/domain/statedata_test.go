package domain

import (
	"strings"
	"testing"

	"github.com/Lercas/prowl/tool/internal/detect"
	"github.com/Lercas/prowl/tool/internal/taxonomy"
)

func TestStateBlobExtractionDecodeDetect(t *testing.T) {
	html := `<html><head>
<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{` +
		`"AWS_ACCESS_KEY_ID":"AKIANAFGYOEYPXU1DSYP",` +
		`"databaseUrl":"postgres:\/\/admin:Pr0dPassw0rd99@db.internal:5432\/orders"}}}</script>
<script>window.__INITIAL_STATE__ = {"stripeKey":"sk_live_x8FqP2mN7kRtY4wZ9aB3cD6e"};</script>
<script>window.appConfig = {"openaiKey":"sk-proj-A1b2C3d4E5f6G7h8I9j0T3BlbkFJk1L2m3N4o5P6q7R8s9t0u1v2w3x4"};</script>
</head></html>`

	items := ExtractStateBlobs(html, "https://acme.com")
	if len(items) == 0 {
		t.Fatal("no state blobs extracted")
	}
	var joined string
	for _, it := range items {
		joined += it.Text + "\n"
	}
	if !strings.Contains(joined, "postgres://admin") { // \/ must be decoded
		t.Errorf("escapes not decoded; got: %q", joined)
	}

	tax, err := taxonomy.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	det := detect.New(tax)
	found := map[string]bool{}
	for _, it := range items {
		for _, m := range det.Scan(it.Text) {
			found[m.Type] = true
		}
	}
	for _, want := range []string{"aws_access_key_id", "db_connection_string", "stripe_secret_key", "openai_api_key"} {
		if !found[want] {
			t.Errorf("expected to detect %s inside state blobs; found=%v", want, found)
		}
	}
}

func TestDecodeUnicodeEscape(t *testing.T) {
	if got := decodeEscapes(`a/b`); got != "a/b" {
		t.Errorf("unicode decode: got %q want a/b", got)
	}
}
