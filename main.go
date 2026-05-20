package main

import (
	"os"

	"github.com/alecthomas/kong"
)

type cliContext struct{}

var cli struct { //nolint:gochecknoglobals // CLI definition, populated by Kong
	Load   loadCmd   `cmd:"" help:"Load and attach the eBPF program."`
	Unload unloadCmd `cmd:"" help:"Detach and unload the eBPF program."`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
		kong.ShortUsageOnError(),
	)
	err := ctx.Run(&cliContext{})
	ctx.FatalIfErrorf(err)
	os.Exit(0)
}
