//go:build !windows

package secretindex

import (
	"io/fs"
	"syscall"
)

func privatePermissions(mode fs.FileMode) bool       { return mode.Perm()&0o077 == 0 }
func checkPlatformPrivacy(string, fs.FileInfo) error { return nil }
func secureNewDirectory(string) error                { return nil }

func singleLink(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
