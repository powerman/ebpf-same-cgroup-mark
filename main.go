package main

import (
	"github.com/alecthomas/kong"
)

var cli struct { //nolint:gochecknoglobals // CLI definition, populated by Kong
	Load   loadCmd   `cmd:"" help:"Load and attach the eBPF program."`
	Unload unloadCmd `cmd:"" help:"Detach and unload the eBPF program."`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
		kong.ShortUsageOnError(),
	)
	ctx.FatalIfErrorf(ctx.Run())
}
