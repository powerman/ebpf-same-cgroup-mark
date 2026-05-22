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
	errMockStat        = errors.New("mock stat error")
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

type testApp struct {
	*check.C

	Ctrl      *gomock.Controller
	MockWorld *MockWorld
	Expect    *MockWorldMockRecorder
	App       main.App
}

func newTestApp(tt *testing.T) *testApp {
	tt.Helper()
	t := &testApp{C: check.T(tt).MustAll()}

	t.Ctrl = gomock.NewController(t)
	t.MockWorld = NewMockWorld(t.Ctrl)
	t.Expect = t.MockWorld.EXPECT()
	t.App = main.NewApp(t.MockWorld)

	return t
}

// TestDo tests all code paths of app.do():
//   - rootCheck error
//   - ensureBPFFS error (mkdir failure, mount failure)
//   - success (BPFFS already mounted, mount fresh)
//
// setup must set method-specific success expectations.
func (t *testApp) TestDo(setup func(), method func() error) {
	t.Helper()

	t.ExpectRootCheckError()
	t.Err(method(), main.ErrMustBeRoot)

	t.ExpectRootCheckSuccess()
	t.ExpectEnsureBPFFSMkdirError()
	t.Match(method(), errMockMkdir.Error())

	t.ExpectRootCheckSuccess()
	t.ExpectEnsureBPFFSMountError()
	t.Match(method(), "mount bpf")

	t.ExpectRootCheckSuccess()
	t.ExpectEnsureBPFFSMounted()
	setup()
	t.Nil(method())

	t.ExpectRootCheckSuccess()
	t.ExpectEnsureBPFFSMount()
	setup()
	t.Nil(method())
}

func (t *testApp) ExpectRootCheckError() {
	t.Expect.OsGeteuid().Return(1000)
}

func (t *testApp) ExpectRootCheckSuccess() {
	t.Expect.OsGeteuid().Return(0)
}

func (t *testApp) ExpectEnsureBPFFSMounted() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(nil)
}

func (t *testApp) ExpectEnsureBPFFSMkdirError() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(errMockMkdir)
}

func (t *testApp) ExpectEnsureBPFFSMountError() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	t.ExpectCmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return([]byte("mount failure details"), errMockMountFailed)
}

func (t *testApp) ExpectEnsureBPFFSMount() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(errMockNotMounted)
	t.Expect.OsMkdirAll(main.BPFRoot, main.BPFMode).Return(nil)
	t.ExpectCmdOutput("mount", "-t", "bpf", "bpf", main.BPFRoot).Return(nil, nil)
}

// ExpectLoadSuccess sets up successful Load-specific expectations (cleanup, temp file, loadall, attach).
func (t *testApp) ExpectLoadSuccess() {
	t.ExpectCleanup(errMockRemove)
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

// ExpectUnloadSuccess sets up successful Unload-specific expectations (cleanup).
func (t *testApp) ExpectUnloadSuccess() {
	t.ExpectCleanup(errMockRemove)
}

// ExpectSetMarkSuccess sets up successful SetMark-specific expectations (bpftool map update).
func (t *testApp) ExpectSetMarkSuccess() {
	t.ExpectCmdRun("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)
}

type cmdRunExpectation struct {
	t    *testApp
	args []any
}

// ExpectCmdRun creates an expectation for ExecCommand(args...) that returns
// a mock command whose Run() is configured to return the given error.
func (t *testApp) ExpectCmdRun(args ...any) *cmdRunExpectation {
	return &cmdRunExpectation{t: t, args: args}
}

func (e *cmdRunExpectation) Return(err error) {
	e.t.Expect.ExecCommand(e.args[0], e.args[1:]...).Return(e.t.newCmdRun(err))
}

type cmdOutputExpectation struct {
	t    *testApp
	args []any
}

// ExpectCmdOutput creates an expectation for ExecCommand(args...) that returns
// a mock command whose CombinedOutput() is configured to return the given (out, err).
func (t *testApp) ExpectCmdOutput(args ...any) *cmdOutputExpectation {
	return &cmdOutputExpectation{t: t, args: args}
}

func (e *cmdOutputExpectation) Return(out []byte, err error) {
	e.t.Expect.ExecCommand(e.args[0], e.args[1:]...).Return(e.t.newCmdOutput(out, err))
}

// newCmdRun creates a MockWorldExecCmd whose Run() returns err.
func (t *testApp) newCmdRun(err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(t.Ctrl)
	result.EXPECT().Run().Return(err)
	return result
}

// newCmdOutput creates a MockWorldExecCmd whose CombinedOutput() returns (out, err).
func (t *testApp) newCmdOutput(out []byte, err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(t.Ctrl)
	result.EXPECT().CombinedOutput().Return(out, err)
	return result
}

type cmdStdoutExpectation struct {
	t    *testApp
	args []any
}

// ExpectCmdStdout creates an expectation for ExecCommand(args...) that returns
// a mock command whose Output() is configured to return the given (out, err).
func (t *testApp) ExpectCmdStdout(args ...any) *cmdStdoutExpectation {
	return &cmdStdoutExpectation{t: t, args: args}
}

func (e *cmdStdoutExpectation) Return(out []byte, err error) {
	e.t.Expect.ExecCommand(e.args[0], e.args[1:]...).Return(e.t.newCmdStdout(out, err))
}

// newCmdStdout creates a MockWorldExecCmd whose Output() returns (out, err).
func (t *testApp) newCmdStdout(out []byte, err error) *MockWorldExecCmd {
	result := NewMockWorldExecCmd(t.Ctrl)
	result.EXPECT().Output().Return(out, err)
	return result
}

// ExpectTempFile sets up successful temp file creation for testing file operations.
func (t *testApp) ExpectTempFile() {
	tf := NewMockWorldOsFile(t.Ctrl)
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(main.BPFObj).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	t.Expect.OsRemove("/tmp/test.bpf.o").Return(nil)
}

// ExpectMounted sets up successful ensureBPFFS (already mounted).
func (t *testApp) ExpectMounted() {
	t.ExpectCmdRun("mountpoint", "-q", main.BPFRoot).Return(nil)
}

// ExpectCleanup sets up the private unload cleanup expectations.
// detachErr controls whether detach returns error (clean state) or nil (BPF state present).
// Does NOT include prepare/rootcheck — use when calling private unload directly.
func (t *testApp) ExpectCleanup(detachErr error) {
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(detachErr)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return([]byte("[]"), nil)
}

// ExpectTempFileError sets up expectations for a temp file operation
// that fails at the given stage:
//
//	createErr != nil → OsCreateTemp fails, no file created
//	writeErr  != nil → file created, Write fails
//	closeErr  != nil → file created, Write succeeds, Close fails
func (t *testApp) ExpectTempFileError(createErr, writeErr, closeErr error) {
	if createErr != nil {
		t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, createErr)
		return
	}
	tf := NewMockWorldOsFile(t.Ctrl)
	t.Expect.OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	writeResult := len(main.BPFObj)
	if writeErr != nil {
		writeResult = 0
	}
	tf.EXPECT().Write(gomock.Any()).Return(writeResult, writeErr)
	tf.EXPECT().Close().Return(closeErr)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	t.Expect.OsRemove("/tmp/test.bpf.o").Return(nil)
}

// Load.

func TestAppLoad_Do(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)
	t.TestDo(t.ExpectLoadSuccess, t.App.Load)
}

func TestAppLoad_WriteTempBPFObjError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)
	t.ExpectTempFileError(errMockMkdir, nil, nil)
	t.ExpectCleanup(errMockRemove)

	err := t.App.Load()
	t.Match(err, errMockMkdir.Error())
}

func TestAppLoad_TempFileWriteError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)
	t.ExpectTempFileError(nil, errMockMkdir, nil)
	t.ExpectCleanup(errMockRemove)

	err := t.App.Load()
	t.Match(err, "write temp file")
}

func TestAppLoad_TempFileCloseError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)
	t.ExpectTempFileError(nil, nil, errMockMkdir)
	t.ExpectCleanup(errMockRemove)

	err := t.App.Load()
	t.Match(err, "close temp file")
}

func TestAppLoad_CleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: program still attached (cgroup show still mentions it).
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	attaches := []byte(`[{"name":"same_cgroup_bind4","attach_type":"cgroup_inet4_bind"}]`)
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return(attaches, nil)

	err := t.App.Load()
	t.Match(err, "cleanup previous state")
}

func TestAppLoad_BPFToolLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)
	t.ExpectTempFile()
	t.ExpectCmdRun("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(errMockLoadall)
	t.ExpectCleanup(errMockRemove)

	err := t.App.Load()
	t.Match(err, "bpftool loadall")
}

func TestAppLoad_AttachError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)
	t.ExpectTempFile()
	t.ExpectCmdRun("bpftool", "prog", "loadall",
		gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).Return(nil)
	entries := main.CgroupAttach()
	for _, att := range entries[:len(entries)-1] {
		t.ExpectCmdRun("bpftool", "cgroup", "attach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(nil)
	}
	lastAtt := entries[len(entries)-1]
	t.ExpectCmdRun("bpftool", "cgroup", "attach",
		main.CgroupRoot, lastAtt.AttachType, "pinned", filepath.Join(main.BPFDir, lastAtt.ProgName),
	).Return(errMockAttach)

	t.ExpectCleanup(nil)

	err := t.App.Load()
	t.Match(err, "attach")
}

func TestAppLoad_MountBPFFSSuccess(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectEnsureBPFFSMount()
	t.ExpectLoadSuccess()

	t.Nil(t.App.Load())
}

func TestAppLoad_Success(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectLoadSuccess()

	t.Nil(t.App.Load())
}

// Unload.

func TestAppUnload_Do(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)
	t.TestDo(t.ExpectUnloadSuccess, t.App.Unload)
}

func TestAppUnload_WithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(errMockRemove)

	t.Nil(t.App.Unload())
}

func TestAppUnload_WithBPF(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCleanup(nil)

	t.Nil(t.App.Unload())
}

func TestAppUnload_CheckUnloadedBPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockRemove)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: BPF pin directory still exists.
	t.Expect.OsStat(main.BPFDir).Return(nil, nil)
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return([]byte("[]"), nil)

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_CheckUnloadedBPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockRemove)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: stat returns an unrelated error (not ErrNotExist).
	t.Expect.OsStat(main.BPFDir).Return(nil, errMockStat)
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return([]byte("[]"), nil)

	err := t.App.Unload()
	t.Match(err, "stat BPF pin dir")
}

func TestAppUnload_CheckUnloadedCgroupShowError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockRemove)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	// checkUnloaded: BPF pin directory cleaned.
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	// checkUnloaded: bpftool cgroup show fails.
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return(nil, errMockBpftool)

	err := t.App.Unload()
	t.Match(err, "cannot verify cgroup attachments")
}

func TestAppUnload_CheckUnloadedCgroupShowJSONError(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	for _, att := range main.CgroupAttach() {
		t.ExpectCmdRun("bpftool", "cgroup", "detach",
			main.CgroupRoot, att.AttachType, "pinned", filepath.Join(main.BPFDir, att.ProgName),
		).Return(errMockRemove)
	}
	t.Expect.OsRemoveAll(main.BPFDir).Return(nil)
	t.Expect.OsStat(main.BPFDir).Return(nil, os.ErrNotExist)
	t.ExpectCmdStdout("bpftool", "--json", "cgroup", "show", main.CgroupRoot).Return([]byte("not-json"), nil)

	err := t.App.Unload()
	t.Match(err, "cannot verify cgroup attachments")
	t.Match(err, "parse bpftool cgroup")
}

// SetMark.

func TestAppSetMark_Do(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)
	t.TestDo(t.ExpectSetMarkSuccess, func() error { return t.App.SetMark(main.Mark(0x10000000)) })
}

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectSetMarkSuccess()

	t.Nil(t.App.SetMark(main.Mark(0x10000000)))
}

func TestAppSetMark_Error(tt *testing.T) {
	tt.Parallel()
	t := newTestApp(tt)

	t.ExpectRootCheckSuccess()
	t.ExpectMounted()
	t.ExpectCmdRun("bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	err := t.App.SetMark(main.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
