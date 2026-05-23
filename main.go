// Load/unload eBPF program that sets SO_MARK on same-cgroup TCP connections.
package main

import (
	_ "embed"

	"github.com/alecthomas/kong"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
)

// BPFObj is the embedded eBPF object file compiled from same-cgroup-mark.bpf.c.
//
//go:embed .cache/same-cgroup-mark.bpf.o
var BPFObj []byte

func main() {
	var cli internal.CLI
	ctx := kong.Parse(&cli,
		kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
		kong.ShortUsageOnError(),
	)
	ctx.BindTo(internal.NewApp(internal.RealWorld{}, BPFObj), (*internal.App)(nil))
	ctx.FatalIfErrorf(ctx.Run())
}
