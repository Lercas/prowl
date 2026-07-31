package verify

import (
	"path/filepath"
	"testing"
)

// Every AI detector shipped under rules/ai must have a provider route. This is a routing
// contract only: the test never sends a live request or embeds a credential.
func TestAITypeVerifierCoverage(t *testing.T) {
	verifierDir := filepath.Join("..", "..", "verifiers")
	set, err := Load(0, verifierDir)
	if err != nil {
		t.Fatalf("load bundled verifiers: %v", err)
	}

	for _, typeID := range []string{
		"anthropic-api-key",
		"anthropic-admin-api-key",
		"assemblyai-api-key",
		"cohere-api-key",
		"deepgram-api-key",
		"deepinfra-api-key",
		"deepseek_api_key",
		"elevenlabs-api-key",
		"fireworks-api-key",
		"google-gemini-api-key",
		"groq-api-key",
		"huggingface-access-token",
		"huggingface-organization-token",
		"langsmith-api-key",
		"langsmith-legacy-api-key",
		"mistral-api-key",
		"openai-api-key",
		"openrouter-api-key",
		"perplexity-api-key",
		"pinecone-api-key",
		"replicate-api-token",
		"stability-api-key",
		"together-api-key",
	} {
		if !set.Supports(typeID) {
			t.Errorf("AI type %q has no live verifier route", typeID)
		}
	}

	for _, verifierID := range []string{"deepinfra", "deepseek", "fireworks", "perplexity"} {
		var found *Verifier
		for _, verifier := range set.Verifiers() {
			if verifier.ID == verifierID {
				found = verifier
				break
			}
		}
		if found == nil {
			t.Fatalf("new AI verifier %q was not loaded", verifierID)
		}
		if bad := exfilRequests(found); len(bad) != 0 {
			t.Errorf("AI verifier %q interpolates a secret into its URL: %v", verifierID, bad)
		}
		for i, request := range found.Requests {
			if request.Method != "GET" {
				t.Errorf("AI verifier %q request %d is %q, want read-only GET", verifierID, i, request.Method)
			}
		}
	}
}
