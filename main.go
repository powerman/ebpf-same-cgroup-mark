// Load/unload eBPF program that sets SO_MARK on same-cgroup TCP connections.
package main

import "github.com/alecthomas/kong"

func main() {
	var cli struct {
		Load   loadCmd   `cmd:"" help:"Load and attach the eBPF program."`
		Unload unloadCmd `cmd:"" help:"Detach and unload the eBPF program."`
	}

	ctx := kong.Parse(&cli,
		kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
		kong.ShortUsageOnError(),
	)
	ctx.FatalIfErrorf(ctx.Run())
}
