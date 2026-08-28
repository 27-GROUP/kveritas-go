//go:build !linux

// The activity tracer is Linux-only (inotify and /proc). Elsewhere the observer is
// a no-op so the binary still builds; macOS and Windows support is future work.
package tracer

import "github.com/Mamadou2727/kveritas-go/internal/session"

type Observer struct{}

func New(root string) *Observer { return &Observer{} }

func (o *Observer) Start() {}

func (o *Observer) SetPID(pid int) {}

func (o *Observer) Stop() *session.RunTrace { return nil }
