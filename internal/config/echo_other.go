//go:build !windows

package config

import (
	"os"
	"os/exec"
)

// disableEcho turns terminal echo off with stty and returns a function that
// turns it back on.
func disableEcho(f *os.File) func() {
	off := exec.Command("stty", "-echo")
	off.Stdin = f
	if off.Run() != nil {
		return func() {}
	}
	return func() {
		on := exec.Command("stty", "echo")
		on.Stdin = f
		_ = on.Run()
	}
}
