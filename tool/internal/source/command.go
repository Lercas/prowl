package source

import (
	"os/exec"

	"github.com/Lercas/prowl/tool/internal/ownedcmd"
)

const maxCommandOutput = ownedcmd.MaxOutput

type commandOutput = ownedcmd.Output

// runOwnedCommand bounds diagnostics and inherited-pipe waits. Unix commands use a fresh process
// group so cancellation and completion also stop workers spawned by this acquisition command.
func runOwnedCommand(cmd *exec.Cmd) (string, error) {
	return ownedcmd.Run(cmd)
}
