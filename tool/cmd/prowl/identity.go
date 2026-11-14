package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Lercas/prowl/tool/internal/localfile"
)

func loadIdentityKey(path string) ([]byte, error) {
	optional := path == ""
	if optional {
		path = filepath.Join(prowlHome(), "identity.key")
		selected, err := localfile.FirstExisting(path)
		if err != nil {
			return nil, errors.New("cannot inspect key file")
		}
		if selected == "" {
			return nil, nil
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("cannot read key file")
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		return nil, errors.New("key must be a small regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key permissions must be 0600")
	}
	f, err := os.OpenFile(path, identityOpenFlags, 0)
	if err != nil {
		return nil, errors.New("cannot read key file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("key file changed during read")
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key permissions must be private")
	}
	data, err := io.ReadAll(io.LimitReader(f, 257))
	if err != nil || len(data) > 256 {
		return nil, errors.New("cannot read key file")
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("key must contain exactly 32 hex-encoded bytes")
	}
	return key, nil
}

func cmdIdentity(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: prowl identity init [-o FILE]")
		return 2
	}
	c, rest, err := parseCommand("identity", args)
	if err != nil {
		return commandParseError(err)
	}
	if args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: prowl identity init [-o FILE]")
		return 2
	}
	if len(rest) != 0 {
		fmt.Fprintln(os.Stderr, "identity init does not accept positional arguments")
		return 2
	}
	path := c.output
	if path == "" {
		path = filepath.Join(prowlHome(), "identity.key")
	}
	// The explicit CLI path is the intended destination; no untrusted scanned data reaches it.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // #nosec G703 -- user-selected output path
		fmt.Fprintln(os.Stderr, "cannot create the key directory")
		return 2
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 2
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G703 -- exclusive creation at user-selected output path
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create the key: the path already exists or is not accessible")
		return 2
	}
	_, err = f.WriteString(hex.EncodeToString(key) + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return 2
	}
	fmt.Fprintln(os.Stdout, "Identity key created:", path)
	return 0
}
