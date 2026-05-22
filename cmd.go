package main

import "errors"

// LoadCmd loads and attaches the eBPF program.
type LoadCmd struct {
	Mark *Mark `help:"Mark mask in hexadecimal (e.g. 0x40000000)." short:"m"`
}

// Run executes the LoadCmd.
func (c *LoadCmd) Run(a App) error {
	err := a.Load()

	if err == nil && c.Mark != nil {
		err = a.SetMark(*c.Mark)
		if err != nil {
			err = errors.Join(err, a.Unload())
		}
	}

	return err
}

// UnloadCmd detaches and unloads the eBPF program.
type UnloadCmd struct{}

// Run executes the UnloadCmd.
func (*UnloadCmd) Run(a App) error {
	return a.Unload()
}
