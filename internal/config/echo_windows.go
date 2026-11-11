//go:build windows

package config

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableEchoInput = 0x0004

// disableEcho clears the console's echo mode and returns a function that
// restores it.
func disableEcho(f *os.File) func() {
	h := f.Fd()
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return func() {}
	}
	procSetConsoleMode.Call(h, uintptr(mode&^enableEchoInput))
	return func() { procSetConsoleMode.Call(h, uintptr(mode)) }
}
