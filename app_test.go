package main_test

import (
	"errors"
	"os"
	"testing"

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

// newApp creates a mock World and App for testing.
func newApp(t *check.C) (*gomock.Controller, *MockWorld, main.App) {
	ctrl := gomock.NewController(t)
	w := NewMockWorld(ctrl)
	return ctrl, w, main.NewApp(w)
}

// newCmdRun creates a MockWorldExecCmd whose Run() returns err.
func newCmdRun(ctrl *gomock.Controller, err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(ctrl)
	result.EXPECT().Run().Return(err)
	return result
}

// newCmdOutput creates a MockWorldExecCmd whose CombinedOutput() returns (out, err).
func newCmdOutput(ctrl *gomock.Controller, out []byte, err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(ctrl)
	result.EXPECT().CombinedOutput().Return(out, err)
	return result
}

// expectTempFile sets up successful temp file creation for testing file operations.
func expectTempFile(ctrl *gomock.Controller, w *MockWorld) {
	tf := NewMockWorldOsFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
}

// expectMounted sets up successful ensureBPFFS (already mounted).
func expectMounted(ctrl *gomock.Controller, w *MockWorld) {
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, nil))
}

// expectUnloadClean sets up a full Unload call with no BPF state to clean up.
func expectUnloadClean(ctrl *gomock.Controller, w *MockWorld) {
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, nil))
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "detach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, errMockRemove))
	}
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().ExecCommand("bpftool", "cgroup", "show", main.CgroupRoot).Return(newCmdOutput(ctrl, nil, nil))
}

// expectUnloadRollback sets up a full Unload call with BPF state to clean up.
func expectUnloadRollback(ctrl *gomock.Controller, w *MockWorld) {
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, nil))
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "detach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().ExecCommand("bpftool", "cgroup", "show", main.CgroupRoot).Return(newCmdOutput(ctrl, nil, nil))
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

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)
	expectUnloadClean(ctrl, w)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_TempFileWriteError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	tf := NewMockWorldOsFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	expectUnloadClean(ctrl, w)

	err := a.Load()
	t.Match(err, "write temp file")
}

func TestAppLoad_TempFileCloseError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	tf := NewMockWorldOsFile(ctrl)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	expectUnloadClean(ctrl, w)

	err := a.Load()
	t.Match(err, "close temp file")
}

func TestAppLoad_EnsureBPFFSError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, errMockNotMounted))
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(errMockMkdir)

	err := a.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_MountBPFFSError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, errMockNotMounted))
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	w.EXPECT().ExecCommand("mount", "-t", "bpf", "bpf", main.BPFRoot).Return(newCmdOutput(ctrl, []byte("mount failure details"), errMockMountFailed))

	err := a.Load()
	t.Match(err, "mount bpf")
}

func TestAppLoad_CleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	// Initial Unload: prepare + detach + remove + checkUnloaded.
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, nil))
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "detach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: program still attached (cgroup show still mentions it).
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().ExecCommand("bpftool", "cgroup", "show", main.CgroupRoot).Return(newCmdOutput(ctrl, []byte("same_cgroup_bind4"), nil))

	err := a.Load()
	t.Match(err, "cleanup previous state")
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	expectTempFile(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(newCmdRun(ctrl, errMockLoadall))
	expectUnloadClean(ctrl, w)

	err := a.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	expectTempFile(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(newCmdRun(ctrl, nil))
	for range 3 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "attach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}
	w.EXPECT().ExecCommand("bpftool", "cgroup", "attach",
		main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).Return(newCmdRun(ctrl, errMockAttach))

	expectUnloadRollback(ctrl, w)

	err := a.Load()
	t.Match(err, "attach")
}

func TestAppLoad_MountBPFFSSuccess(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).Return(newCmdRun(ctrl, errMockNotMounted))
	w.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	w.EXPECT().ExecCommand("mount", "-t", "bpf", "bpf", main.BPFRoot).Return(newCmdOutput(ctrl, nil, nil))
	expectUnloadClean(ctrl, w)
	expectTempFile(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(newCmdRun(ctrl, nil))
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "attach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}

	t.Nil(a.Load())
}

func TestAppLoad_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	expectUnloadClean(ctrl, w)
	expectTempFile(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(newCmdRun(ctrl, nil))
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "attach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}

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

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "detach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, errMockRemove))
	}
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().ExecCommand("bpftool", "cgroup", "show", main.CgroupRoot).Return(newCmdOutput(ctrl, nil, nil))

	t.Nil(a.Unload())
}

func TestAppUnload_WithBPF(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	for range 4 {
		w.EXPECT().ExecCommand("bpftool", "cgroup", "detach",
			main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
		).Return(newCmdRun(ctrl, nil))
	}
	w.EXPECT().OsRemoveAll(main.BPFDir).Return(nil)
	w.EXPECT().OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	w.EXPECT().ExecCommand("bpftool", "cgroup", "show", main.CgroupRoot).Return(newCmdOutput(ctrl, nil, nil))

	t.Nil(a.Unload())
}

// SetMark.

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(newCmdRun(ctrl, nil))

	t.Nil(a.SetMark(main.Mark(0x10000000)))
}

func TestAppSetMark_Error(tt *testing.T) {
	tt.Parallel()
	t := check.T(tt).MustAll()

	ctrl, w, a := newApp(t)
	w.EXPECT().OsGeteuid().Return(0)
	expectMounted(ctrl, w)
	w.EXPECT().ExecCommand("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(newCmdRun(ctrl, errMockBpftool))

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
