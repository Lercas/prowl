//go:build windows

package main

import "os"

// Lstat and SameFile bracket the read; the selected file must be regular.
const identityOpenFlags = os.O_RDONLY
