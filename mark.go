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

// Parse parses a hexadecimal string into a Mark value.
func (m *Mark) Parse(s string) error {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	if err != nil {
		return fmt.Errorf("invalid mark value %q: %w", s, err)
	}
	if v > math.MaxUint32 {
		return fmt.Errorf("%w: 0x%X", ErrMarkOverflow, v)
	}
	*m = Mark(v)
	return nil
}

// UnmarshalText implements [encoding.TextUnmarshaler] for Kong flag parsing.
func (m *Mark) UnmarshalText(text []byte) error {
	return m.Parse(string(text))
}

// ToLE converts a Mark value to a little-endian hexadecimal string array for bpftool.
func (m *Mark) ToLE() [4]string {
	hex := fmt.Sprintf("%08x", uint32(*m))
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}
