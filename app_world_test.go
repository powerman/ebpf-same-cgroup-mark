package main_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/powerman/check"

	main "github.com/powerman/ebpf-same-cgroup-mark"
)

var (
	errWorldAttach      = errors.New("world attach error")
	errWorldBpftool     = errors.New("world bpftool error")
	errWorldClose       = errors.New("world close error")
	errWorldCreateTemp  = errors.New("world create temp error")
	errWorldLoadall     = errors.New("world loadall error")
	errWorldMkdir       = errors.New("world mkdir error")
	errWorldMountFailed = errors.New("world mount failed error")
	errWorldNotMounted  = errors.New("world not mounted error")
	errWorldRemove      = errors.New("world remove error")
	errWorldStat        = errors.New("world stat error")
	errWorldWrite       = errors.New("world write error")
)

type worldState struct {
	euid         int
	mounted      bool
	bpfDirExists bool
	attached     map[string]struct{}
	tempFiles    map[string]struct{}
	nextTempID   int
	markBytes    [4]string

	mkdirErr      error
	mountErr      error
	mountOutput   []byte
	createTempErr error
	tempWriteErr  error
	tempCloseErr  error
	loadallErr    error
	mapUpdateErr  error
	cgroupShowErr error
	cgroupShowRaw []byte
	statErr       error
	removeAllErr  error
	removeErr     error

	attachErr map[string]error
	detachErr map[string]error
}

type statefulAppTest struct {
	*check.C

	World *mockWorld
	App   main.App
	state *worldState
}

type dummyFileInfo struct{}

func (dummyFileInfo) Name() string       { return main.BPFDir }
func (dummyFileInfo) Size() int64        { return 0 }
func (dummyFileInfo) Mode() os.FileMode  { return 0o750 }
func (dummyFileInfo) ModTime() time.Time { return time.Time{} }
func (dummyFileInfo) IsDir() bool        { return true }
func (dummyFileInfo) Sys() any           { return nil }

func cgroupShowJSONWorld(names ...string) []byte {
	entries := make([]main.CgroupAttach, 0, len(names))
	for _, name := range names {
		for _, att := range main.CgroupAttaches() {
			if att.Name == name {
				entries = append(entries, att)
				break
			}
		}
	}
	out, _ := json.Marshal(entries)
	return out
}

func newStatefulAppTest(tt *testing.T) *statefulAppTest {
	tt.Helper()
	t := &statefulAppTest{C: check.T(tt).MustAll()}

	t.state = &worldState{
		euid:      0,
		mounted:   true,
		attached:  make(map[string]struct{}),
		tempFiles: make(map[string]struct{}),
		attachErr: make(map[string]error),
		detachErr: make(map[string]error),
	}
	t.World = &mockWorld{state: t.state}
	t.App = main.NewApp(t.World)

	return t
}

// mockWorld implements main.World with stateful behavior driven by worldState.
type mockWorld struct {
	state *worldState
}

func (m *mockWorld) OsGeteuid() int { return m.state.euid }

func (m *mockWorld) OsMkdirAll(_ string, _ os.FileMode) error { return m.state.mkdirErr }

func (m *mockWorld) OsRemove(name string) error {
	delete(m.state.tempFiles, name)
	return m.state.removeErr
}

func (m *mockWorld) OsRemoveAll(_ string) error {
	if m.state.removeAllErr != nil {
		return m.state.removeAllErr
	}
	m.state.bpfDirExists = false
	return nil
}

func (m *mockWorld) OsStat(_ string) (os.FileInfo, error) {
	if m.state.statErr != nil {
		return nil, m.state.statErr
	}
	if m.state.bpfDirExists {
		return dummyFileInfo{}, nil
	}
	return nil, os.ErrNotExist
}

func (m *mockWorld) OsCreateTemp(_, _ string) (main.WorldOsFile, error) {
	if m.state.createTempErr != nil {
		return nil, m.state.createTempErr
	}
	path := "/tmp/stateful-" + strconv.Itoa(m.state.nextTempID) + ".bpf.o"
	m.state.nextTempID++
	m.state.tempFiles[path] = struct{}{}
	return &mockOsFile{
		name: path,
		writeFn: func(_ []byte) (int, error) {
			if m.state.tempWriteErr != nil {
				return 0, m.state.tempWriteErr
			}
			return len(main.BPFObj), nil
		},
		closeFn: func() error {
			return m.state.tempCloseErr
		},
	}, nil
}

func (m *mockWorld) ExecCommand(name string, args ...string) main.WorldExecCmd {
	switch {
	case name == "mountpoint" && slices.Equal(args, []string{"-q", main.BPFRoot}):
		return &worldCmdMock{
			runFn: func() error {
				if m.state.mounted {
					return nil
				}
				return errWorldNotMounted
			},
		}

	case name == "mount" && slices.Equal(args, []string{"-t", "bpf", "bpf", main.BPFRoot}):
		return &worldCmdMock{
			combinedOutputFn: func() ([]byte, error) {
				if m.state.mountErr != nil {
					return m.state.mountOutput, m.state.mountErr
				}
				m.state.mounted = true
				return nil, nil
			},
		}

	case name == "bpftool" && len(args) >= 2 && args[0] == "prog" && args[1] == "loadall":
		return &worldCmdMock{
			runFn: func() error {
				if m.state.loadallErr != nil {
					return m.state.loadallErr
				}
				m.state.bpfDirExists = true
				return nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "cgroup" && args[1] == "attach":
		return &worldCmdMock{
			runFn: func() error {
				attachType := args[3]
				progName := filepath.Base(args[5])
				err := m.state.attachErr[progName]
				if err != nil {
					return err
				}
				m.state.bpfDirExists = true
				m.state.attached[progName] = struct{}{}
				_ = attachType
				return nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "cgroup" && args[1] == "detach":
		return &worldCmdMock{
			runFn: func() error {
				attachType := args[3]
				progName := filepath.Base(args[5])
				err := m.state.detachErr[progName]
				if err != nil {
					return err
				}
				delete(m.state.attached, progName)
				_ = attachType
				return nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "map" && args[1] == "update" &&
		args[2] == "pinned" && args[3] == main.BPFDir+"/maps/same_cgroup_mark_cfg":
		return &worldCmdMock{
			runFn: func() error {
				if m.state.mapUpdateErr != nil {
					return m.state.mapUpdateErr
				}
				last := len(args) - 4
				m.state.markBytes = [4]string{args[last], args[last+1], args[last+2], args[last+3]}
				return nil
			},
		}

	case name == "bpftool" && slices.Equal(args, []string{"--json", "cgroup", "show", main.CgroupRoot}):
		return &worldCmdMock{
			outputFn: func() ([]byte, error) {
				if m.state.cgroupShowErr != nil {
					return nil, m.state.cgroupShowErr
				}
				if m.state.cgroupShowRaw != nil {
					return m.state.cgroupShowRaw, nil
				}
				return cgroupShowJSONWorld(slices.Sorted(maps.Keys(m.state.attached))...), nil
			},
		}

	default:
		panic(fmt.Sprintf("unexpected command: %s %v", name, args))
	}
}

// worldCmdMock implements main.WorldExecCmd with configurable function fields.
type worldCmdMock struct {
	runFn            func() error
	combinedOutputFn func() ([]byte, error)
	outputFn         func() ([]byte, error)
}

func (c *worldCmdMock) Run() error {
	if c.runFn == nil {
		panic("worldCmdMock: Run() not configured")
	}
	return c.runFn()
}

func (c *worldCmdMock) CombinedOutput() ([]byte, error) {
	if c.combinedOutputFn == nil {
		panic("worldCmdMock: CombinedOutput() not configured")
	}
	return c.combinedOutputFn()
}

func (c *worldCmdMock) Output() ([]byte, error) {
	if c.outputFn == nil {
		panic("worldCmdMock: Output() not configured")
	}
	return c.outputFn()
}

// mockOsFile implements main.WorldOsFile with configurable function fields.
type mockOsFile struct {
	name    string
	writeFn func([]byte) (int, error)
	closeFn func() error
}

func (f *mockOsFile) Name() string                { return f.name }
func (f *mockOsFile) Write(p []byte) (int, error) { return f.writeFn(p) }
func (f *mockOsFile) Close() error                { return f.closeFn() }

func (t *statefulAppTest) attachedProgramNames() []string {
	result := make([]string, 0, len(t.state.attached))
	for name := range t.state.attached {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

func runDoFailures(tt *testing.T, call func(t *statefulAppTest) error) {
	tt.Helper()

	tt.Run("RootCheckError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.euid = 1000
		t.Err(call(t), main.ErrMustBeRoot)
	})

	tt.Run("EnsureBPFFSMkdirError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.mounted = false
		t.state.mkdirErr = errWorldMkdir
		t.Match(call(t), errWorldMkdir.Error())
	})

	tt.Run("EnsureBPFFSMountError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.mounted = false
		t.state.mountErr = errWorldMountFailed
		t.state.mountOutput = []byte("mount failure details")
		t.Match(call(t), "mount bpf")
	})
}

func TestAppLoad_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.Load() })
}

func TestAppLoad_StatefulWriteTempCreateError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.createTempErr = errWorldCreateTemp

	err := t.App.Load()
	t.Match(err, "create temp file")
	t.Len(t.attachedProgramNames(), 0)
	t.False(t.state.bpfDirExists)
}

func TestAppLoad_StatefulWriteTempWriteError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.tempWriteErr = errWorldWrite

	err := t.App.Load()
	t.Match(err, "write temp file")
	t.Len(t.attachedProgramNames(), 0)
	t.False(t.state.bpfDirExists)
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulWriteTempCloseError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.tempCloseErr = errWorldClose

	err := t.App.Load()
	t.Match(err, "close temp file")
	t.Len(t.attachedProgramNames(), 0)
	t.False(t.state.bpfDirExists)
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulCleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.bpfDirExists = true
	t.state.attached["same_cgroup_bind4"] = struct{}{}
	t.state.detachErr["same_cgroup_bind4"] = errWorldRemove

	err := t.App.Load()
	t.Match(err, "cleanup previous state")
	t.Match(err, "BPF program still attached")
}

func TestAppLoad_StatefulLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.loadallErr = errWorldLoadall

	err := t.App.Load()
	t.Match(err, "bpftool loadall")
	t.Len(t.attachedProgramNames(), 0)
	t.False(t.state.bpfDirExists)
	// The temp object is cleaned up by deferred OsRemove.
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulAttachErrorRollsBack(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	entries := main.CgroupAttaches()
	t.state.attachErr[entries[len(entries)-1].Name] = errWorldAttach

	err := t.App.Load()
	t.Match(err, "bpftool attach")
	t.Len(t.attachedProgramNames(), 0)
	t.False(t.state.bpfDirExists)
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulSuccessMounted(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)

	t.Nil(t.App.Load())
	t.True(t.state.mounted)
	t.True(t.state.bpfDirExists)
	t.DeepEqual(t.attachedProgramNames(), []string{
		"same_cgroup_bind4",
		"same_cgroup_bind6",
		"same_cgroup_connect4",
		"same_cgroup_connect6",
	})
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulSuccessMountFresh(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.mounted = false

	t.Nil(t.App.Load())
	t.True(t.state.mounted)
	t.True(t.state.bpfDirExists)
	t.DeepEqual(t.attachedProgramNames(), []string{
		"same_cgroup_bind4",
		"same_cgroup_bind6",
		"same_cgroup_connect4",
		"same_cgroup_connect6",
	})
}

func TestAppUnload_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.Unload() })
}

func TestAppUnload_StatefulWithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)

	t.Nil(t.App.Unload())
	t.False(t.state.bpfDirExists)
	t.Len(t.attachedProgramNames(), 0)
}

func TestAppUnload_StatefulWithBPF(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.bpfDirExists = true
	for _, att := range main.CgroupAttaches() {
		t.state.attached[att.Name] = struct{}{}
	}

	t.Nil(t.App.Unload())
	t.False(t.state.bpfDirExists)
	t.Len(t.attachedProgramNames(), 0)
}

func TestAppUnload_StatefulBPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.bpfDirExists = true
	t.state.removeAllErr = errWorldRemove

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_StatefulBPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.statErr = errWorldStat

	err := t.App.Unload()
	t.Match(err, "stat BPF pin dir")
	t.Match(err, errWorldStat.Error())
}

func TestAppUnload_StatefulCgroupShowError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.cgroupShowErr = errWorldBpftool

	err := t.App.Unload()
	t.Match(err, "cannot verify cgroup attachments")
}

func TestAppUnload_StatefulMalformedJSON(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.cgroupShowRaw = []byte("{")

	err := t.App.Unload()
	t.Match(err, "cannot verify cgroup attachments")
	t.Match(err, "parse bpftool cgroup")
}

func TestAppSetMark_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.SetMark(main.Mark(0x10000000)) })
}

func TestAppSetMark_StatefulSuccess(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	mark := main.Mark(0x10000000)

	t.Nil(t.App.SetMark(mark))
	t.DeepEqual(t.state.markBytes, mark.ToLE())
}

func TestAppSetMark_StatefulError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.mapUpdateErr = errWorldBpftool

	err := t.App.SetMark(main.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
