package main

import (
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Errors.
var (
	ErrInvalidMarkValue = errors.New("invalid mark value")
	ErrMarkOverflow     = errors.New("mark value exceeds 32-bit maximum (0xFFFFFFFF)")
)

// Mark is a validated 32-bit mark value.
// It implements [encoding.TextUnmarshaler] for use as a Kong custom type.
type Mark uint32

// UnmarshalText implements [encoding.TextUnmarshaler] for Kong flag parsing.
func (m *Mark) UnmarshalText(text []byte) error {
	return m.parse(string(text))
}

// parse parses a hexadecimal string into a Mark value.
func (m *Mark) parse(s string) error {
	hex := s
	if len(hex) > 2 && (hex[:2] == "0x" || hex[:2] == "0X") {
		hex = hex[2:]
	}
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidMarkValue, s)
	}
	if v > math.MaxUint32 {
		return fmt.Errorf("%w: %q", ErrMarkOverflow, s)
	}
	*m = Mark(v)
	return nil
}

// ToLE converts a Mark value to a little-endian hexadecimal string array for bpftool.
func (m *Mark) ToLE() [4]string {
	hex := fmt.Sprintf("%08x", *m)
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}
