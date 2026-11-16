package lsp

import "testing"

func TestEditorGenericIdentifierNoiseAndLiteralRecall(t *testing.T) {
	e := newTestEngine(t)
	for _, text := range []string{`const bypass=routesV2;`, `const passwordInput2=document.getElementById("password");`, `api_key=` + "\x4b" + `p9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL;`} {
		if ds := scanDiagnostics(e, "file:///app.js", text); len(ds) > 0 {
			t.Fatal("editor reports a code identifier as a credential")
		}
	}
	for _, text := range []string{`api_key="` + "\x4b" + `p9aZ2bYwcX4dWqeV8fUmgThS6iRnjQ7sL";`, `password="hunter2";`} {
		if ds := scanDiagnostics(e, "file:///app.js", text); len(ds) == 0 {
			t.Fatal("editor lost a configured literal")
		}
	}
}

// drainPublishes reads every framed message from buf and returns the count of publishDiagnostics
// frames plus the params of the last one.
