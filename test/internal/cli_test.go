package internal_test

import (
	"errors"
	"io"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/powerman/check"
	gomock "go.uber.org/mock/gomock"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
	port "github.com/powerman/ebpf-same-cgroup-mark/test/internal"
)

var (
	errMockApp      = errors.New("mock app error")
	errMockRollback = errors.New("mock rollback error")
)

// kongParse parses command-line arguments using Kong for testing.
func kongParse(t *check.TB, args ...string) (ctx *kong.Context, cmd internal.CLI, err error) {
	t.Helper()
	k, err := kong.New(&cmd,
		kong.Writers(io.Discard, io.Discard),
		kong.Exit(func(int) {}),
	)
	if err != nil {
		return nil, cmd, err
	}
	ctx, err = k.Parse(args)
	return ctx, cmd, err
}

// kongRun parses command-line arguments using Kong, binds the App, and runs the command.
func kongRun(t *check.TB, a internal.App, args ...string) error {
	t.Helper()
	ctx, _, err := kongParse(t, args...)
	t.Nil(err)
	ctx.BindTo(a, (*internal.App)(nil))
	return ctx.Run()
}

func TestLoadCmd_Mark(t *testing.T) {
	t.Parallel()

	t.Run("NotProvided", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		_, cmd, err := kongParse(t, "load")
		t.Nil(err)
		t.Nil(cmd.Load.Mark)
	})

	t.Run("Valid", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		_, cmd, err := kongParse(t, "load", "--mark", "0x20000000")
		t.Nil(err)
		t.DeepEqual(cmd.Load.Mark, new(internal.Mark(0x20000000)))
	})

	t.Run("Invalid", func(tt *testing.T) {
		tt.Parallel()
		t := check.Must(tt)
		_, _, err := kongParse(t, "load", "--mark", "invalid")
		t.Match(err, "invalid mark value")
	})
}

func TestCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		expect   func(a *port.MockApp)
		wantErrs []error
	}{
		{
			name: "LoadError",
			args: []string{"load"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Load().Return(errMockApp)
			},
			wantErrs: []error{errMockApp},
		},
		{
			name: "LoadSetMarkError",
			args: []string{"load", "--mark", "0x10000000"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Load().Return(nil)
				a.EXPECT().SetMark(internal.Mark(0x10000000)).Return(errMockApp)
				a.EXPECT().Unload().Return(nil)
			},
			wantErrs: []error{errMockApp},
		},
		{
			name: "LoadSetMarkRollbackFailed",
			args: []string{"load", "--mark", "0x10000000"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Load().Return(nil)
				a.EXPECT().SetMark(internal.Mark(0x10000000)).Return(errMockApp)
				a.EXPECT().Unload().Return(errMockRollback)
			},
			wantErrs: []error{errMockApp, errMockRollback},
		},
		{
			name: "LoadSuccess",
			args: []string{"load"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Load().Return(nil)
			},
		},
		{
			name: "LoadWithMarkSuccess",
			args: []string{"load", "--mark", "0x10000000"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Load().Return(nil)
				a.EXPECT().SetMark(internal.Mark(0x10000000)).Return(nil)
			},
		},
		{
			name: "UnloadError",
			args: []string{"unload"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Unload().Return(errMockApp)
			},
			wantErrs: []error{errMockApp},
		},
		{
			name: "UnloadSuccess",
			args: []string{"unload"},
			expect: func(a *port.MockApp) {
				a.EXPECT().Unload().Return(nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := check.Must(tt)
			a := port.NewMockApp(gomock.NewController(t))
			tc.expect(a)
			err := kongRun(t, a, tc.args...)
			if len(tc.wantErrs) == 0 {
				t.Nil(err)
			}
			for _, wantErr := range tc.wantErrs {
				t.Err(err, wantErr)
			}
		})
	}
}
