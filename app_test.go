package main_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

// Package-level sentinel errors for mocks (err113 requires static errors).
var (
	errMockAttach      = errors.New("mock attach error")
	errMockBpftool     = errors.New("mock bpftool error")
	errMockLoadall     = errors.New("mock loadall error")
	errMockMkdir       = errors.New("mock mkdir error")
	errMockMountFailed = errors.New("mock mount failed error")
	errMockNotMounted  = errors.New("mock not mounted error")
	errMockRemove      = errors.New("mock remove error")
)

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

type test struct {
	*check.C

	Ctrl      *gomock.Controller
	MockWorld *MockWorld
	Expect    *MockWorldMockRecorder
	App       main.App
}

func newTest(tt *testing.T) *test {
	tt.Helper()
	t := &test{C: check.T(tt).MustAll()}

	t.Ctrl = gomock.NewController(t)
	t.MockWorld = NewMockWorld(t.Ctrl)
	t.Expect = t.MockWorld.EXPECT()
	t.Expect.OsIsNotExist(gomock.Any()).DoAndReturn(os.IsNotExist).AnyTimes()
	t.App = main.NewApp(t.MockWorld)

	return t
}

// TestDo tests all code paths of app.do():
//   - rootCheck error
//   - ensureBPFFS error (mkdir failure, mount failure)
//   - success (BPFFS already mounted, mount fresh)
//
// setup must set method-specific success expectations.
func (t *test) TestDo(setup func(), method func() error) {
	t.Helper()

	t.expectRootCheckError()
	t.Err(method(), main.ErrMustBeRoot)

	t.expectRootCheckSuccess()
	t.expectEnsureBPFFSMkdirError()
	t.Match(method(), errMockMkdir.Error())

	t.expectRootCheckSuccess()
	t.expectEnsureBPFFSMountError()
	t.Match(method(), "mount bpf")

	t.expectRootCheckSuccess()
	t.expectEnsureBPFFSMounted()
	setup()
	t.Nil(method())

	t.expectRootCheckSuccess()
	t.expectEnsureBPFFSMount()
	setup()
	t.Nil(method())
}

func (t *test) expectRootCheckError() {
	t.Expect.OsGeteuid().Return(1000)
}

func (t *test) expectRootCheckSuccess() {
	t.Expect.OsGeteuid().Return(0)
}

func (t *test) expectEnsureBPFFSMounted() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(nil)
}

func (t *test) expectEnsureBPFFSMkdirError() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(errMockMkdir)
}

func (t *test) expectEnsureBPFFSMountError() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	t.ExpectCmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return([]byte("mount failure details"), errMockMountFailed)
}

func (t *test) expectEnsureBPFFSMount() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	t.ExpectCmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return(nil, nil)
}

// expectLoadSuccess sets up successful Load-specific expectations (cleanup, temp file, loadall, attach).
func (t *test) expectLoadSuccess() {
	t.ExpectCleanupClean()
	t.ExpectTempFile()
	t.ExpectCmdRun("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "attach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
}

// expectUnloadSuccess sets up successful Unload-specific expectations (cleanup).
func (t *test) expectUnloadSuccess() {
	t.ExpectCleanupClean()
}

// expectSetMarkSuccess sets up successful SetMark-specific expectations (bpftool map update).
func (t *test) expectSetMarkSuccess() {
	t.ExpectCmdRun("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)
}

type cmdRunExpectation struct {
	t    *test
	args []any
}

// ExpectCmdRun creates an expectation for ExecCommand(args...) that returns
// a mock command whose Run() is configured to return the given error.
func (t *test) ExpectCmdRun(args ...any) *cmdRunExpectation {
	return &cmdRunExpectation{t: t, args: args}
}

func (e *cmdRunExpectation) Return(err error) {
	e.t.Expect.ExecCommand(e.args[0], e.args[1:]...).Return(e.t.newCmdRun(err))
}

type cmdOutputExpectation struct {
	t    *test
	args []any
}

// ExpectCmdOutput creates an expectation for ExecCommand(args...) that returns
// a mock command whose CombinedOutput() is configured to return the given (out, err).
func (t *test) ExpectCmdOutput(args ...any) *cmdOutputExpectation {
	return &cmdOutputExpectation{t: t, args: args}
}

func (e *cmdOutputExpectation) Return(out []byte, err error) {
	e.t.Expect.ExecCommand(e.args[0], e.args[1:]...).Return(e.t.newCmdOutput(out, err))
}

// newCmdRun creates a MockWorldExecCmd whose Run() returns err.
func (t *test) newCmdRun(err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(t.Ctrl)
	result.EXPECT().Run().Return(err)
	return result
}

// newCmdOutput creates a MockWorldExecCmd whose CombinedOutput() returns (out, err).
func (t *test) newCmdOutput(out []byte, err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(t.Ctrl)
	result.EXPECT().CombinedOutput().Return(out, err)
	return result
}

// ExpectTempFile sets up successful temp file creation for testing file operations.
func (t *test) ExpectTempFile() {
	tf := NewMockWorldOsFile(t.Ctrl)
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(main.BPFObj).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	t.Expect.OsRemove("/tmp/test.bpf.o").Return(nil)
}

// ExpectMounted sets up successful ensureBPFFS (already mounted).
func (t *test) ExpectMounted() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(nil)
}

// ExpectCleanupClean sets up the private unload cleanup expectations
// with detach returning "not found" errors (clean state).
// Does NOT include prepare/rootcheck — use when calling private unload directly.
func (t *test) ExpectCleanupClean() {
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockRemove)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	t.ExpectCmdOutput("bpftool", "cgroup", "show", main.CgroupRoot).Return(nil, nil)
}

// ExpectCleanupRollback sets up the private unload cleanup expectations
// with successful detach (BPF state present).
// Does NOT include prepare/rootcheck — use when calling private unload directly.
func (t *test) ExpectCleanupRollback() {
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	t.ExpectCmdOutput("bpftool", "cgroup", "show", main.CgroupRoot).Return(nil, nil)
}

// Load.

func TestAppLoad_Do(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)
	t.TestDo(t.expectLoadSuccess, t.App.Load)
}

func TestAppLoad_WriteTempBPFObjError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)
	t.ExpectCleanupClean()

	err := t.App.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_TempFileWriteError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()
	tf := NewMockWorldOsFile(t.Ctrl)
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	t.Expect.OsRemove("/tmp/test.bpf.o").Return(nil)
	t.ExpectCleanupClean()

	err := t.App.Load()
	t.Match(err, "write temp file")
}

func TestAppLoad_TempFileCloseError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()
	tf := NewMockWorldOsFile(t.Ctrl)
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	t.Expect.OsRemove("/tmp/test.bpf.o").Return(nil)
	t.ExpectCleanupClean()

	err := t.App.Load()
	t.Match(err, "close temp file")
}

func TestAppLoad_CleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: program still attached (cgroup show still mentions it).
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	t.ExpectCmdOutput("bpftool", "cgroup", "show", main.CgroupRoot).Return([]byte("same_cgroup_bind4"), nil)

	err := t.App.Load()
	t.Match(err, "cleanup previous state")
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()
	t.ExpectTempFile()
	t.ExpectCmdRun("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(errMockLoadall)
	t.ExpectCleanupClean()

	err := t.App.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()
	t.ExpectTempFile()
	t.ExpectCmdRun("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	for _, att := range main.CgroupAttach()[:3] {
		t.ExpectCmdRun("bpftool", "cgroup", "attach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
	{
		att := main.CgroupAttach()[3]
		t.ExpectCmdRun("bpftool", "cgroup", "attach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockAttach)
	}

	t.ExpectCleanupRollback()

	err := t.App.Load()
	t.Match(err, "attach")
}

func TestAppLoad_MountBPFFSSuccess(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.expectEnsureBPFFSMount()
	t.expectLoadSuccess()

	t.Nil(t.App.Load())
}

func TestAppLoad_Success(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.expectLoadSuccess()

	t.Nil(t.App.Load())
}

// Unload.

func TestAppUnload_Do(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)
	t.TestDo(t.expectUnloadSuccess, t.App.Unload)
}

func TestAppUnload_WithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupClean()

	t.Nil(t.App.Unload())
}

func TestAppUnload_WithBPF(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanupRollback()

	t.Nil(t.App.Unload())
}

// SetMark.

func TestAppSetMark_Do(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)
	t.TestDo(t.expectSetMarkSuccess, func() error { return t.App.SetMark(main.Mark(0x10000000)) })
}

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.expectSetMarkSuccess()

	t.Nil(t.App.SetMark(main.Mark(0x10000000)))
}

func TestAppSetMark_Error(tt *testing.T) {
	tt.Parallel()
	t := newTest(tt)

	t.expectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCmdRun("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	err := t.App.SetMark(main.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
