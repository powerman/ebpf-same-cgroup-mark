package internal_test

import (
	"testing"

	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
)

func TestMarkUnmarshalText(tt *testing.T) {
	tt.Parallel()

	tests := []struct {
		input   string
		want    internal.Mark
		wantErr string
	}{
		{"0", 0, ""},
		{"1234", 0x1234, ""},
		{"10000000", 0x10000000, ""},
		{"0x000", 0, ""},
		{"0x1", 1, ""},
		{"0x20000000", 0x20000000, ""},
		{"0x10000000", 0x10000000, ""},
		{"0xFFFFFFFF", 0xFFFFFFFF, ""},
		{"0x1FFFFFFFF", 0, "mark value exceeds 32-bit maximum"},
		{"not-a-number", 0, "invalid mark value"},
		{"1g", 0, "invalid mark value"},
		{"0x1g", 0, "invalid mark value"},
	}
	for _, tc := range tests {
		tt.Run(tc.input, func(tt *testing.T) {
			tt.Parallel()
			t := check.T(tt).MustAll()
			var m internal.Mark
			err := m.UnmarshalText([]byte(tc.input))
			if tc.wantErr != "" {
				t.Match(err, tc.wantErr)
			} else {
				t.Nil(err)
				t.Equal(m, tc.want)
			}
		})
	}
}

func TestMarkToLE(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	tests := []struct {
		mark internal.Mark
		want [4]string
	}{
		{0x00100000, [4]string{"00", "00", "10", "00"}},
		{0x00000001, [4]string{"01", "00", "00", "00"}},
		{0x10000000, [4]string{"00", "00", "00", "10"}},
		{0xFFFFFFFF, [4]string{"ff", "ff", "ff", "ff"}},
		{0xABCDEF01, [4]string{"01", "ef", "cd", "ab"}},
	}
	for _, tc := range tests {
		t.DeepEqual(tc.mark.ToLE(), tc.want)
	}
}
