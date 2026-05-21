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

// newApp creates a mock World and App for testing.
func newApp(t *check.C) (*gomock.Controller, *MockWorld, main.App) {
	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	return ctrl, w, main.NewApp(w)
}

// expectTempFile sets up successful temp file creation for testing file operations.
func expectTempFile(ctrl *gomock.Controller, w *MockWorld) {
	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
}

// Load.

func TestAppLoad_RootCheckError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Err(a.Load(), main.ErrMustBeRoot)
}

func TestAppLoad_WriteTempBPFObjError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_EnsureBPFFSError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_CleanupPinDirError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(errMockRemove)

	err := a.Load()
	t.Match(err, "cleanup old pin dir")
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(errMockLoadall)

	err := a.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(3)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(errMockAttach)

	err := a.Load()
	t.Match(err, "attach")
}

func TestAppLoad_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)

	t.Nil(a.Load())
}

// Unload.

func TestAppUnload_RootCheckError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Err(a.Unload(), main.ErrMustBeRoot)
}

func TestAppUnload_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	t.Nil(a.Unload())
}

// RootCheck.

func TestAppRootCheck_AsRoot(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)

	t.Nil(a.RootCheck())
}

func TestAppRootCheck_AsNonRoot(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Err(a.RootCheck(), main.ErrMustBeRoot)
}

// UnloadBPF.

func TestAppUnloadBPF_NotExists(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	t.Nil(a.UnloadBPF())
}

func TestAppUnloadBPF_Exists(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsStat(main.PinDir).Return(dummyFileInfo{}, nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "detach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)

	t.Nil(a.UnloadBPF())
}

// SetMark.

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)

	t.Nil(a.SetMark(main.Mark(0x10000000)))
}

func TestAppSetMark_Error(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	err := a.SetMark(main.Mark(0x10000000))
	t.Match(err, "set mark")
}

// EnsureBPFFS.

func TestAppEnsureBPFFS_MkdirError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	err := a.EnsureBPFFS()
	t.Match(err, errMockMkdir.Error())
}

func TestAppEnsureBPFFS_AlreadyMounted(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)

	t.Nil(a.EnsureBPFFS())
}

func TestAppEnsureBPFFS_MountSuccess(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return(nil, nil)

	t.Nil(a.EnsureBPFFS())
}

func TestAppEnsureBPFFS_MountError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return([]byte("mount failure details"), errMockMountFailed)

	err := a.EnsureBPFFS()
	t.Match(err, "mount bpf")
}

// WriteTempBPFObj.

func TestAppWriteTempBPFObj_CreateTempError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(nil, errMockMkdir)

	_, err := a.WriteTempBPFObj()
	t.Match(err, "create temp file")
}

func TestAppWriteTempBPFObj_WriteError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	_, err := a.WriteTempBPFObj()
	t.Match(err, "write temp file")
}

func TestAppWriteTempBPFObj_CloseError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	_, err := a.WriteTempBPFObj()
	t.Match(err, "close temp file")
}

// RunCmd.

func TestAppRunCmd_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().CmdRun(gomock.Any(), "echo", "hello", "world").Return(nil)

	err := a.RunCmd("echo", "hello", "world")
	t.Nil(err)
}

func TestAppRunCmd_Error(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().CmdRun(gomock.Any(), "false").Return(errMockCmd)

	err := a.RunCmd("false")
	t.NotNil(err)
}

// CgroupAttach.

func TestCgroupAttach(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	entries := main.CgroupAttach()
	t.Len(entries, 4)
	t.Equal(entries[0], main.CgroupAttachEntry{"same_cgroup_bind4", "cgroup_inet4_bind"})
	t.Equal(entries[1], main.CgroupAttachEntry{"same_cgroup_bind6", "cgroup_inet6_bind"})
	t.Equal(entries[2], main.CgroupAttachEntry{"same_cgroup_connect4", "cgroup_inet4_connect"})
	t.Equal(entries[3], main.CgroupAttachEntry{"same_cgroup_connect6", "cgroup_inet6_connect"})
}
