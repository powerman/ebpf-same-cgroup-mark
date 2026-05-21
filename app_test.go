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

// expectMounted sets up successful EnsureBPFFS steps (already mounted).
func expectMounted(w *MockWorld) {
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", main.BPFRoot).Return(nil)
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
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_TempFileWriteError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	err := a.Load()
	t.Match(err, "write temp file")
}

func TestAppLoad_TempFileCloseError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	tf := NewMockTempFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	err := a.Load()
	t.Match(err, "close temp file")
}

func TestAppLoad_EnsureBPFFSError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(errMockMkdir)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_MountBPFFSError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return([]byte("mount failure details"), errMockMountFailed)

	err := a.Load()
	t.Match(err, "mount bpf")
}

func TestAppLoad_CleanupPinDirError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	expectMounted(w)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(errMockRemove)

	err := a.Load()
	t.Match(err, "cleanup old pin dir")
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	expectMounted(w)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(errMockLoadall)

	err := a.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	expectMounted(w)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(3)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).Return(errMockAttach)

	err := a.Load()
	t.Match(err, "attach")
}

func TestAppLoad_MountBPFFSSuccess(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return(nil, nil)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)

	t.Nil(a.Load())
}

func TestAppLoad_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	expectTempFile(ctrl, w)
	expectMounted(w)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
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

func TestAppUnload_WithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)

	t.Nil(a.Unload())
}

func TestAppUnload_WithBPF(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.BPFDir).Return(dummyFileInfo{}, nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "detach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)

	t.Nil(a.Unload())
}

// SetMark.

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	_, w, a := newApp(t)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
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
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	err := a.SetMark(main.Mark(0x10000000))
	t.Match(err, "set mark")
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
