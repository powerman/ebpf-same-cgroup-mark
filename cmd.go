package main

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// Errors.
var (
	ErrMarkOverflow = errors.New("mark value exceeds 32-bit maximum (0xFFFFFFFF)")
)

// LoadCmd loads and attaches the eBPF program.
type LoadCmd struct {
	Mark string `help:"Mark mask (e.g. 0x40000000)." short:"m"`
}

// Run executes the LoadCmd.
func (c *LoadCmd) Run(a App) error {
	err := a.Load()
	if err != nil {
		return err
	}

	if c.Mark != "" {
		mark, err := ParseMark(c.Mark)
		if err != nil {
			return err
		}
		return a.SetMark(mark)
	}

	return nil
}

// UnloadCmd detaches and unloads the eBPF program.
type UnloadCmd struct{}

// Run executes the UnloadCmd.
func (*UnloadCmd) Run(a App) error {
	return a.Unload()
}

// ParseMark parses a hexadecimal string into a uint32 mark value.
func ParseMark(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	if err != nil {
		return 0, fmt.Errorf("invalid mark value %q: %w", s, err)
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("%w: 0x%X", ErrMarkOverflow, v)
	}
	return uint32(v), nil
}
