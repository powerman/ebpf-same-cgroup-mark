package main_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

// Package-level sentinel errors for mocks (err113 requires static errors).
var (
	errMockCmd         = errors.New("mock cmd error")
	errMockMkdir       = errors.New("mock mkdir error")
	errMockNotMounted  = errors.New("mock not mounted error")
	errMockMountFailed = errors.New("mock mount failed error")
	errMockLoadall     = errors.New("mock loadall error")
	errMockAttach      = errors.New("mock attach error")
	errMockRemove      = errors.New("mock remove error")
	errMockBpftool     = errors.New("mock bpftool error")
)

// dummyFileInfo implements os.FileInfo for tests (avoids nilnil linter).
type dummyFileInfo struct{}

func (dummyFileInfo) Name() string       { return "" }
func (dummyFileInfo) Size() int64        { return 0 }
func (dummyFileInfo) Mode() os.FileMode  { return 0 }
func (dummyFileInfo) ModTime() time.Time { return time.Time{} }
func (dummyFileInfo) IsDir() bool        { return false }
func (dummyFileInfo) Sys() any           { return nil }

func TestAppLoad_RootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Equal(a.Load(), main.ErrMustBeRoot)
}

func TestAppLoad_EnsureBPFFSError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	a := main.NewApp(w)
	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_WriteTempBPFObjError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)

	a := main.NewApp(w)
	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(errMockLoadall)

	a := main.NewApp(w)
	err := a.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(errMockAttach)

	a := main.NewApp(w)
	err := a.Load()
	t.Match(err, "attach")
}

func TestAppLoad_CleanupPinDirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(errMockRemove)

	a := main.NewApp(w)
	err := a.Load()
	t.Match(err, "cleanup old pin dir")
}

func TestAppLoad_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)

	a := main.NewApp(w)
	t.Nil(a.Load())
}

func TestAppUnload_RootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Equal(a.Unload(), main.ErrMustBeRoot)
}

func TestAppUnload_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	t.Nil(a.Unload())
}

func TestAppRootCheck_AsRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsGeteuid().Return(0)

	t.Nil(a.RootCheck())
}

func TestAppRootCheck_AsNonRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Equal(a.RootCheck(), main.ErrMustBeRoot)
}

func TestAppRunCmd_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().CmdRun(gomock.Any(), "echo", "hello", "world").Return(nil)

	err := a.RunCmd("echo", "hello", "world")
	t.Nil(err)
}

func TestAppRunCmd_Error(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().CmdRun(gomock.Any(), "false").Return(errMockCmd)

	err := a.RunCmd("false")
	t.NotNil(err)
}

func TestAppEnsureBPFFS_MkdirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	a := main.NewApp(w)
	err := a.EnsureBPFFS()
	t.Match(err, errMockMkdir.Error())
}

func TestAppEnsureBPFFS_AlreadyMounted(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)

	a := main.NewApp(w)
	t.Nil(a.EnsureBPFFS())
}

func TestAppEnsureBPFFS_MountSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return(nil, nil)

	a := main.NewApp(w)
	t.Nil(a.EnsureBPFFS())
}

func TestAppEnsureBPFFS_MountError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return([]byte("mount failure details"), errMockMountFailed)

	a := main.NewApp(w)
	err := a.EnsureBPFFS()
	t.Match(err, "mount bpf")
}

func TestAppSetMark_Success(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)

	a := main.NewApp(w)
	t.Nil(a.SetMark(main.Mark(0x40000000)))
}

func TestAppSetMark_Error(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	a := main.NewApp(w)
	err := a.SetMark(main.Mark(0x40000000))
	t.Match(err, "set mark")
}

func TestAppUnloadBPF_NotExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	t.Nil(a.UnloadBPF())
}

func TestAppUnloadBPF_Exists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	a := main.NewApp(w)
	w.EXPECT().OsStat(main.PinDir).Return(dummyFileInfo{}, nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "detach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)

	t.Nil(a.UnloadBPF())
}

func TestAppWriteTempBPFObj_CreateTempError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(nil, errMockMkdir)

	a := main.NewApp(w)
	_, err := a.WriteTempBPFObj()
	t.Match(err, "create temp file")
}

func TestAppWriteTempBPFObj_WriteError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	tf := NewMockTempFile(ctrl)

	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	a := main.NewApp(w)
	_, err := a.WriteTempBPFObj()
	t.Match(err, "write temp file")
}

func TestAppWriteTempBPFObj_CloseError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	tf := NewMockTempFile(ctrl)

	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	a := main.NewApp(w)
	_, err := a.WriteTempBPFObj()
	t.Match(err, "close temp file")
}

func TestCgroupAttach(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	entries := main.CgroupAttach()
	t.Len(entries, 4)
	t.Equal(entries[0], main.CgroupAttachEntry{"same_cgroup_bind4", "cgroup_inet4_bind"})
	t.Equal(entries[1], main.CgroupAttachEntry{"same_cgroup_bind6", "cgroup_inet6_bind"})
	t.Equal(entries[2], main.CgroupAttachEntry{"same_cgroup_connect4", "cgroup_inet4_connect"})
	t.Equal(entries[3], main.CgroupAttachEntry{"same_cgroup_connect6", "cgroup_inet6_connect"})
}
