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

// Mark is a validated 32-bit mark value.
// It implements [encoding.TextUnmarshaler] for use as a Kong custom type.
type Mark uint32

// UnmarshalText implements [encoding.TextUnmarshaler] for Kong flag parsing.
func (m *Mark) UnmarshalText(text []byte) error {
	v, err := ParseMark(string(text))
	if err != nil {
		return err
	}
	*m = Mark(v)
	return nil
}

// LoadCmd loads and attaches the eBPF program.
type LoadCmd struct {
	Mark *Mark `help:"Mark mask (e.g. 0x40000000)." short:"m"`
}

// Run executes the LoadCmd.
func (c *LoadCmd) Run(a App) error {
	err := a.Load()
	if err != nil {
		return err
	}

	if c.Mark != nil {
		return a.SetMark(uint32(*c.Mark))
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
