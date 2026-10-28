package main

import (
	"fmt"
	"os"
)

func rejectUnsupportedServeStages(c commonFlags) int {
	if c.mlEmbed || c.mlModel != "" || c.mlURL != "" || c.verify || c.verifiedOnly || c.verifyAll || c.failOnVerified || c.semantic || c.reconstruct || c.showSecrets || c.identityKeyFile != "" {
		fmt.Fprintln(os.Stderr, "serve supports L1 and rule templates with redacted output; ML, verification, semantic, reconstruction, raw secrets and identity keys require scan/MCP")
		return 2
	}
	return 0
}
