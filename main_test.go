package main

import (
	"os"
	"testing"

	"github.com/alecthomas/kong"
)

func TestCLILoadDefaults(t *testing.T) {
	cli, err := parseArgs("load")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if cli.Load.Mark != "" {
		t.Fatalf("expected mark=\"\", got %q", cli.Load.Mark)
	}
}

func TestCLILoadWithMark(t *testing.T) {
	cli, err := parseArgs("load", "-m", "0x40000000")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	if cli.Load.Mark != "0x40000000" {
		t.Fatalf("expected mark=\"0x40000000\", got %q", cli.Load.Mark)
	}
}

func TestParseMark(t *testing.T) {
	tests := []struct {
		input string
		want  uint
	}{
		{"0x40000000", 0x40000000},
		{"0x20000000", 0x20000000},
		{"0x1", 1},
		{"40000000", 0x40000000},
	}
	for _, tc := range tests {
		got, err := parseMark(tc.input)
		if err != nil {
			t.Fatalf("parseMark(%q): %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("parseMark(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestParseMarkInvalid(t *testing.T) {
	_, err := parseMark("not-a-number")
	if err == nil {
		t.Fatal("expected error for invalid mark")
	}
}

func TestCLIUnload(t *testing.T) {
	_, err := parseArgs("unload")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	_, err := parseArgs("reload")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestWriteTempBPFObj(t *testing.T) {
	path, err := writeTempBPFObj()
	if err != nil {
		t.Fatal("writeTempBPFObj:", err)
	}
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read temp file:", err)
	}

	if len(data) != len(bpfObj) {
		t.Fatalf("size mismatch: got %d, want %d", len(data), len(bpfObj))
	}
	for i := range data {
		if data[i] != bpfObj[i] {
			t.Fatalf("byte %d mismatch: got %02x, want %02x", i, data[i], bpfObj[i])
		}
	}
}

func TestMarkToLE(t *testing.T) {
	tests := []struct {
		mark uint
		want [4]string
	}{
		{0x40000000, [4]string{"00", "00", "00", "40"}},
		{0x00000001, [4]string{"01", "00", "00", "00"}},
		{0x10000000, [4]string{"00", "00", "00", "10"}},
		{0x1FFFFFFFF, [4]string{"ff", "ff", "ff", "ff"}},
		{0x1ABCDEF01, [4]string{"01", "ef", "cd", "ab"}},
	}
	for _, tc := range tests {
		got := markToLE(tc.mark)
		if got != tc.want {
			t.Fatalf("markToLE(0x%x) = %v, want %v", tc.mark, got, tc.want)
		}
	}
}

// parseArgs creates a test parser, parses args, and returns the populated CLI struct.
func parseArgs(args ...string) (*testCLI, error) {
	cli := &testCLI{}
	parser, err := kong.New(cli,
		kong.Description("test"),
		kong.Exit(func(int) {}),
	)
	if err != nil {
		return nil, err
	}
	_, err = parser.Parse(args)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

type testCLI struct {
	Load   loadCmd   `cmd:""`
	Unload unloadCmd `cmd:""`
}
