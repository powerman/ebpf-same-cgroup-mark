package cli

import (
	"github.com/powerman/ebpf-same-cgroup-mark/internal/app"
	"github.com/powerman/ebpf-same-cgroup-mark/internal/out/world"
)

// NewApp wires the application with the real world adapter.
func NewApp(bpfObj []byte) app.App {
	return app.NewApp(world.RealWorld{}, bpfObj)
}
