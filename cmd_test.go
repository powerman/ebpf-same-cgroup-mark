package main_test

import (
	"errors"
	"testing"

	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

var errMockApp = errors.New("mock app error")

func TestLoadCmdRun_LoadError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Load().Return(errMockApp)

	cmd := &main.LoadCmd{}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestLoadCmdRun_ParseMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)

	cmd := &main.LoadCmd{Mark: "not-a-valid-mark"}
	err := cmd.Run(a)
	t.Match(err, "invalid mark value")
}

func TestLoadCmdRun_SetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)
	a.EXPECT().SetMark(uint32(0x40000000)).Return(errMockApp)

	cmd := &main.LoadCmd{Mark: "0x40000000"}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestLoadCmdRun_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)

	cmd := &main.LoadCmd{Mark: ""}
	t.Nil(cmd.Run(a))
}

func TestLoadCmdRun_SuccessWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Load().Return(nil)
	a.EXPECT().SetMark(uint32(0x40000000)).Return(nil)

	cmd := &main.LoadCmd{Mark: "0x40000000"}
	t.Nil(cmd.Run(a))
}

func TestUnloadCmdRun_UnloadError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Unload().Return(errMockApp)

	cmd := &main.UnloadCmd{}
	t.Equal(cmd.Run(a), errMockApp)
}

func TestUnloadCmdRun_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	a := main.NewMockApp(ctrl)
	a.EXPECT().Unload().Return(nil)

	cmd := &main.UnloadCmd{}
	t.Nil(cmd.Run(a))
}
