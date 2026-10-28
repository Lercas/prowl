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
)

func loadIdentityKey(path string) ([]byte, error) {
	optional := path == ""
	if optional {
		path = filepath.Join(prowlHome(), "identity.key")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && optional {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot read key file")
	}
	if !info.Mode().IsRegular() || info.Size() > 256 {
		return nil, errors.New("key must be a small regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key permissions must be 0600")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, errors.New("cannot read key file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("key file changed during read")
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
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "Использование: prowl identity init [-o FILE]")
		return 2
	}
	var path string
	remaining := args[1:]
	for len(remaining) > 0 {
		arg := remaining[0]
		remaining = remaining[1:]
		switch {
		case arg == "--output" || arg == "-o":
			if len(remaining) == 0 {
				fmt.Fprintln(os.Stderr, "Нужен путь после --output")
				return 2
			}
			path = remaining[0]
			remaining = remaining[1:]
			if path == "" || strings.HasPrefix(path, "-") {
				fmt.Fprintln(os.Stderr, "Нужен путь после --output")
				return 2
			}
		case strings.HasPrefix(arg, "--output="):
			path = strings.TrimPrefix(arg, "--output=")
			if path == "" {
				return 2
			}
		default:
			fmt.Fprintln(os.Stderr, "Неподдерживаемый аргумент identity init")
			return 2
		}
	}
	if path == "" {
		path = filepath.Join(prowlHome(), "identity.key")
	}
	// The explicit CLI path is the intended destination; no untrusted scanned data reaches it.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // #nosec G703 -- user-selected output path
		fmt.Fprintln(os.Stderr, "Не удалось создать каталог ключа")
		return 2
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 2
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G703 -- exclusive creation at user-selected output path
	if err != nil {
		fmt.Fprintln(os.Stderr, "Не удалось создать ключ: путь уже занят или недоступен")
		return 2
	}
	_, err = f.WriteString(hex.EncodeToString(key) + "\n")
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return 2
	}
	fmt.Fprintln(os.Stdout, "Ключ идентичности создан:", path)
	return 0
}
