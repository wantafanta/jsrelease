//go:build !windows

package logger

import "os"

func enableVT(*os.File) bool { return true }
