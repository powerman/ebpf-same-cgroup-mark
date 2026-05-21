package main_test

import (
	"io"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/powerman/check"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

func TestLoadCmd_MarkFlag(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	t.Run("Valid", func(ttt *testing.T) {
		t := check.T(ttt)
		var cli main.CLI
		k, err := kong.New(&cli,
			kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
			kong.ShortUsageOnError(),
			kong.Writers(io.Discard, io.Discard),
			kong.Exit(func(int) {}),
		)
		t.Nil(err)
		_, err = k.Parse([]string{"load", "--mark", "0x40000000"})
		t.Nil(err)
		t.NotNil(cli.Load.Mark)
		t.Equal(uint32(0x40000000), uint32(*cli.Load.Mark))
	})

	t.Run("Invalid", func(ttt *testing.T) {
		t := check.T(ttt)
		var cli main.CLI
		k, err := kong.New(&cli,
			kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
			kong.ShortUsageOnError(),
			kong.Writers(io.Discard, io.Discard),
			kong.Exit(func(int) {}),
		)
		t.Nil(err)
		_, err = k.Parse([]string{"load", "--mark", "invalid"})
		t.NotNil(err)
		t.Match(err, "invalid mark value")
	})

	t.Run("NotProvided", func(ttt *testing.T) {
		t := check.T(ttt)
		var cli main.CLI
		k, err := kong.New(&cli,
			kong.Description("Set SO_MARK on TCP sockets in the same cgroup."),
			kong.ShortUsageOnError(),
			kong.Writers(io.Discard, io.Discard),
			kong.Exit(func(int) {}),
		)
		t.Nil(err)
		_, err = k.Parse([]string{"load"})
		t.Nil(err)
		t.Nil(cli.Load.Mark)
	})
}

func TestMarkToLE(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

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
		m := main.Mark(tc.mark)
		t.DeepEqual(m.ToLE(), tc.want)
	}
}

func TestMarkParse(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

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
		var m main.Mark
		t.Nil(m.Parse(tc.input))
		t.Equal(uint32(m), tc.want)
	}
}

func TestMarkParse_Invalid(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var m main.Mark
	t.NotNil(m.Parse("not-a-number"))
}

func TestMarkParse_Overflow(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var m main.Mark
	t.NotNil(m.Parse("0x1FFFFFFFF"))
}

func TestMarkParse_MaxUint32(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var m main.Mark
	t.Nil(m.Parse("0xFFFFFFFF"))
	t.Equal(uint32(m), uint32(0xFFFFFFFF))
}
