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
	a.EXPECT().SetMark(uint32(0x40000000)).Return(errMockApp)

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
	a.EXPECT().SetMark(uint32(0x40000000)).Return(nil)

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
	a.EXPECT().SetMark(uint32(0x40000000)).Return(nil)

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
