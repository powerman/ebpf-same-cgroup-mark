package main_test

import (
	"errors"
	"io"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

var errMockApp = errors.New("mock app error")

func TestLoadCmd_Mark(t *testing.T) {
	t.Parallel()

	parse := func(t *check.C, args ...string) (cli main.CLI, err error) {
		t.Helper()
		k, err := kong.New(&cli,
			kong.Writers(io.Discard, io.Discard),
			kong.Exit(func(int) {}),
		)
		if err != nil {
			return cli, err
		}
		_, err = k.Parse(args)
		return cli, err
	}

	t.Run("NotProvided", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		cli, err := parse(t, "load")
		t.Nil(err)
		t.Nil(cli.Load.Mark)
	})

	t.Run("Valid", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		cli, err := parse(t, "load", "--mark", "0x20000000")
		t.Nil(err)
		t.DeepEqual(cli.Load.Mark, new(main.Mark(0x20000000)))
	})

	t.Run("Invalid", func(tt *testing.T) {
		tt.Parallel()
		t := check.T(tt).MustAll()
		_, err := parse(t, "load", "--mark", "invalid")
		t.Match(err, "invalid mark value")
	})
}

func TestLoadCmdRun_LoadError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Load().Return(errMockApp)

	cmd := &main.LoadCmd{}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestLoadCmdRun_SetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)
	a.EXPECT().SetMark(main.Mark(0x40000000)).Return(errMockApp)

	mark := main.Mark(0x40000000)
	cmd := &main.LoadCmd{Mark: &mark}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestLoadCmdRun_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)

	cmd := &main.LoadCmd{}
	t.Nil(cmd.Run(a))
}

func TestLoadCmdRun_SuccessWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)
	a.EXPECT().SetMark(main.Mark(0x40000000)).Return(nil)

	mark := main.Mark(0x40000000)
	cmd := &main.LoadCmd{Mark: &mark}
	t.Nil(cmd.Run(a))
}

func TestLoadCmdRun_WithKongBind(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)
	a.EXPECT().SetMark(main.Mark(0x40000000)).Return(nil)

	var cli main.CLI
	k, err := kong.New(&cli,
		kong.Writers(io.Discard, io.Discard),
		kong.Exit(func(int) {}),
	)
	t.Nil(err)
	ctx, err := k.Parse([]string{"load", "--mark", "0x40000000"})
	t.Nil(err)

	ctx.BindTo(a, (*main.App)(nil))
	err = ctx.Run()
	t.Nil(err)
}

func TestUnloadCmdRun_UnloadError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Unload().Return(errMockApp)

	cmd := &main.UnloadCmd{}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestUnloadCmdRun_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	a := NewMockApp(ctrl)
	a.EXPECT().Unload().Return(nil)

	cmd := &main.UnloadCmd{}
	t.Nil(cmd.Run(a))
}
