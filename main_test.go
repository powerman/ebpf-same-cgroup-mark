package main

import (
	"os"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/powerman/check"
)

func TestCLILoadDefaults(tt *testing.T) {
	t := check.T(tt).MustAll()
	cli, err := parseArgs("load")
	t.Nil(err)
	t.Equal(cli.Load.Mark, "")
}

func TestCLILoadWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	cli, err := parseArgs("load", "-m", "0x40000000")
	t.Nil(err)
	t.Equal(cli.Load.Mark, "0x40000000")
}

func TestParseMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	tests := []struct {
		input string
		want  uint32
	}{
		{"0x40000000", 0x40000000},
		{"0x20000000", 0x20000000},
		{"0x1", 1},
		{"40000000", 0x40000000},
	}
	for _, tc := range tests {
		got, err := parseMark(tc.input)
		t.Nil(err)
		t.Equal(got, tc.want)
	}
}

func TestParseMarkInvalid(tt *testing.T) {
	t := check.T(tt).MustAll()
	_, err := parseMark("not-a-number")
	t.NotNil(err)
}

func TestParseMarkOverflow(tt *testing.T) {
	t := check.T(tt).MustAll()
	_, err := parseMark("0x1FFFFFFFF")
	t.NotNil(err)
}

func TestParseMarkMaxUint32(tt *testing.T) {
	t := check.T(tt).MustAll()
	v, err := parseMark("0xFFFFFFFF")
	t.Nil(err)
	t.Equal(v, uint32(0xFFFFFFFF))
}

func TestCLIUnload(tt *testing.T) {
	t := check.T(tt).MustAll()
	_, err := parseArgs("unload")
	t.Nil(err)
}

func TestCLIUnknownCommand(tt *testing.T) {
	t := check.T(tt).MustAll()
	_, err := parseArgs("reload")
	t.NotNil(err)
}

func TestWriteTempBPFObj(tt *testing.T) {
	t := check.T(tt).MustAll()
	path, err := writeTempBPFObj()
	t.Nil(err)
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	t.Nil(err)

	t.Equal(len(data), len(bpfObj))
	t.DeepEqual(data, bpfObj)
}

func TestMarkToLE(tt *testing.T) {
	t := check.T(tt).MustAll()
	tests := []struct {
		mark uint32
		want [4]string
	}{
		{0x40000000, [4]string{"00", "00", "00", "40"}},
		{0x00000001, [4]string{"01", "00", "00", "00"}},
		{0x10000000, [4]string{"00", "00", "00", "10"}},
		{0xFFFFFFFF, [4]string{"ff", "ff", "ff", "ff"}},
		{0xABCDEF01, [4]string{"01", "ef", "cd", "ab"}},
	}
	for _, tc := range tests {
		t.DeepEqual(markToLE(tc.mark), tc.want)
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
