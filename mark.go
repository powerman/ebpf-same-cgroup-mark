package main

import (
	"errors"
	"fmt"
	"math"
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
	return m.Parse(string(text))
}

// Parse parses a hexadecimal string into a Mark value.
func (m *Mark) Parse(s string) error {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
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

// ToLE converts a Mark value to a little-endian hexadecimal string array for bpftool.
func (m *Mark) ToLE() [4]string {
	hex := fmt.Sprintf("%08x", uint32(*m))
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}
