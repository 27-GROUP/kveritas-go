package main

import (
	"os"
	"runtime"
	"sync"

	"golang.org/x/term"
)

const (
	toneID       = "93;1"
	toneRunID    = "96;1"
	toneCurrent  = "35"
	toneFaded    = "90"
	toneBranch   = "32"
	toneActive   = "33"
	toneModified = "34;1"
	toneAdded    = "32;1"
	toneRemoved  = "31;1"
)

var colorOn = sync.OnceValue(func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" || runtime.GOOS == "windows" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
})

func paint(tone, s string) string {
	if tone == "" || s == "" || !colorOn() {
		return s
	}
	return "\x1b[" + tone + "m" + s + "\x1b[0m"
}
