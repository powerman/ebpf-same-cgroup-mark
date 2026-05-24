package internal_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
)

var (
	testBPFObj = []byte("test-bpf-object")

	errWorldAttach      = errors.New("world attach error")
	errWorldBpftool     = errors.New("world bpftool error")
	errWorldClose       = errors.New("world close error")
	errWorldLoadall     = errors.New("world loadall error")
	errWorldMkdir       = errors.New("world mkdir error")
	errWorldMountFailed = errors.New("world mount failed error")
	errWorldNotMounted  = errors.New("world not mounted error")
	errWorldRemove      = errors.New("world remove error")
	errWorldStat        = errors.New("world stat error")
	errWorldWrite       = errors.New("world write error")
)

// trimRoot strips the leading "/" from absolute paths
// so they can be used as keys in fstest.MapFS.
func trimRoot(p string) string { return strings.TrimLeft(p, "/") }

// state holds the current state of the simulated world.
type state struct {
	euid       int
	mounted    bool
	fs         fstest.MapFS
	tempFiles  map[string]struct{}
	nextTempID int
	attached   map[string]struct{}
	markBytes  [4]string
}

// faults configures which operations should return errors.
type faults struct {
	mkdir         error
	mount         error
	mountOutput   []byte
	createTemp    error
	tempWrite     error
	tempClose     error
	loadall       error
	mapUpdate     error
	cgroupShow    error
	cgroupShowRaw []byte
	stat          error
	removeAll     error
	remove        error
	attach        map[string]error
	detach        map[string]error
}

type statefulAppTest struct {
	*check.C

	World  *mockWorld
	App    internal.App
	state  *state
	faults *faults
}

func cgroupShowJSONWorld(names ...string) []byte {
	entries := make([]internal.CgroupAttach, 0, len(names))
	for _, name := range names {
		for _, att := range internal.CgroupAttaches() {
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

	t.state = &state{
		euid:      0,
		mounted:   true,
		fs:        make(fstest.MapFS),
		tempFiles: make(map[string]struct{}),
		attached:  make(map[string]struct{}),
	}
	t.faults = &faults{
		attach: make(map[string]error),
		detach: make(map[string]error),
	}
	t.World = &mockWorld{state: t.state, faults: t.faults}
	t.App = internal.NewApp(t.World, testBPFObj)

	return t
}

// mockWorld implements main.World with stateful behavior driven by worldState and faults.
type mockWorld struct {
	state  *state
	faults *faults
}

func (m *mockWorld) OsGeteuid() int { return m.state.euid }

func (m *mockWorld) OsMkdirAll(path string, perm os.FileMode) error {
	if m.faults.mkdir != nil {
		return m.faults.mkdir
	}
	m.state.fs[trimRoot(path)] = &fstest.MapFile{Mode: os.ModeDir | perm}
	return nil
}

func (m *mockWorld) OsRemove(name string) error {
	delete(m.state.tempFiles, name)
	delete(m.state.fs, trimRoot(name))
	return m.faults.remove
}

func (m *mockWorld) OsRemoveAll(path string) error {
	if m.faults.removeAll != nil {
		return m.faults.removeAll
	}
	delete(m.state.fs, trimRoot(path))
	return nil
}

func (m *mockWorld) OsStat(name string) (os.FileInfo, error) {
	if m.faults.stat != nil {
		return nil, m.faults.stat
	}
	return fs.Stat(m.state.fs, trimRoot(name))
}

func (m *mockWorld) OsCreateTemp(_, _ string) (internal.WorldOsFile, error) {
	if m.faults.createTemp != nil {
		return nil, m.faults.createTemp
	}
	path := "/tmp/stateful-" + strconv.Itoa(m.state.nextTempID) + ".bpf.o"
	m.state.nextTempID++
	m.state.tempFiles[path] = struct{}{}
	return &mockOsFile{
		name: path,
		writeFn: func(_ []byte) (int, error) {
			if m.faults.tempWrite != nil {
				return 0, m.faults.tempWrite
			}
			return len(testBPFObj), nil
		},
		closeFn: func() error {
			return m.faults.tempClose
		},
	}, nil
}

func (m *mockWorld) ExecCommand(name string, args ...string) internal.WorldExecCmd {
	switch {
	case name == "mountpoint" && slices.Equal(args, []string{"-q", internal.BPFRoot}):
		return &worldCmdMock{
			runFn: func() error {
				if m.state.mounted {
					return nil
				}
				return errWorldNotMounted
			},
		}

	case name == "mount" && slices.Equal(args, []string{"-t", "bpf", "bpf", internal.BPFRoot}):
		return &worldCmdMock{
			combinedOutputFn: func() ([]byte, error) {
				if m.faults.mount != nil {
					return m.faults.mountOutput, m.faults.mount
				}
				m.state.mounted = true
				return nil, nil
			},
		}

	case name == "bpftool" && len(args) >= 2 && args[0] == "prog" && args[1] == "loadall":
		return &worldCmdMock{
			combinedOutputFn: func() ([]byte, error) {
				if m.faults.loadall != nil {
					return nil, m.faults.loadall
				}
				m.state.fs[trimRoot(internal.BPFDir)] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
				return nil, nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "cgroup" && args[1] == "attach":
		return &worldCmdMock{
			runFn: func() error {
				progName := filepath.Base(args[5])
				err := m.faults.attach[progName]
				if err != nil {
					return err
				}
				m.state.fs[trimRoot(internal.BPFDir)] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
				m.state.attached[progName] = struct{}{}
				return nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "cgroup" && args[1] == "detach":
		return &worldCmdMock{
			runFn: func() error {
				progName := filepath.Base(args[5])
				err := m.faults.detach[progName]
				if err != nil {
					return err
				}
				delete(m.state.attached, progName)
				return nil
			},
		}

	case name == "bpftool" && len(args) >= 4 &&
		args[0] == "map" && args[1] == "update" &&
		args[2] == "pinned" && args[3] == internal.BPFDir+"/maps/same_cgroup_mark_cfg":
		return &worldCmdMock{
			runFn: func() error {
				if m.faults.mapUpdate != nil {
					return m.faults.mapUpdate
				}
				last := len(args) - 4
				m.state.markBytes = [4]string{args[last], args[last+1], args[last+2], args[last+3]}
				return nil
			},
		}

	case name == "bpftool" && slices.Equal(args, []string{"--json", "cgroup", "show", internal.CgroupRoot}):
		return &worldCmdMock{
			outputFn: func() ([]byte, error) {
				if m.faults.cgroupShow != nil {
					return nil, m.faults.cgroupShow
				}
				if m.faults.cgroupShowRaw != nil {
					return m.faults.cgroupShowRaw, nil
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

func (t *statefulAppTest) assertClean() {
	t.Len(t.attachedProgramNames(), 0)
	t.Len(t.state.tempFiles, 0)
	_, err := fs.Stat(t.state.fs, trimRoot(internal.BPFDir))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("expected BPF dir to not exist, but it does")
	}
}

func (t *statefulAppTest) assertAttachedAll() {
	expected := make([]string, 0, len(internal.CgroupAttaches()))
	for _, att := range internal.CgroupAttaches() {
		expected = append(expected, att.Name)
	}
	t.DeepEqual(t.attachedProgramNames(), expected)
}

func runDoFailures(tt *testing.T, call func(t *statefulAppTest) error) {
	tt.Helper()

	tt.Run("RootCheckError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.euid = 1000
		t.Err(call(t), internal.ErrMustBeRoot)
	})

	tt.Run("EnsureBPFFSMkdirError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.mounted = false
		t.faults.mkdir = errWorldMkdir
		t.Match(call(t), errWorldMkdir.Error())
	})

	tt.Run("EnsureBPFFSMountError", func(tt *testing.T) {
		tt.Parallel()
		t := newStatefulAppTest(tt)
		t.state.mounted = false
		t.faults.mount = errWorldMountFailed
		t.faults.mountOutput = []byte("mount failure details")
		t.Match(call(t), "mount bpf")
	})
}

func TestAppLoad_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.Load() })
}

func TestAppLoad_StatefulWriteTempErrors(tt *testing.T) {
	tt.Parallel()

	tests := []struct {
		name     string
		setup    func(t *statefulAppTest)
		errMatch string
	}{
		{name: "CreateError", setup: func(t *statefulAppTest) { t.faults.createTemp = errWorldMkdir }, errMatch: "create temp file"},
		{name: "WriteError", setup: func(t *statefulAppTest) { t.faults.tempWrite = errWorldWrite }, errMatch: "write temp file"},
		{name: "CloseError", setup: func(t *statefulAppTest) { t.faults.tempClose = errWorldClose }, errMatch: "close temp file"},
	}

	for _, tc := range tests {
		tt.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := newStatefulAppTest(tt)
			tc.setup(t)
			err := t.App.Load()
			t.Match(err, tc.errMatch)
			t.assertClean()
		})
	}
}

func TestAppLoad_StatefulCleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.fs[trimRoot(internal.BPFDir)] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
	t.state.attached["same_cgroup_bind4"] = struct{}{}
	t.faults.detach["same_cgroup_bind4"] = errWorldRemove

	err := t.App.Load()
	t.Match(err, "cleanup previous state")
	t.Match(err, "BPF program still attached")
}

func TestAppLoad_StatefulLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.loadall = errWorldLoadall

	err := t.App.Load()
	t.Match(err, "bpftool loadall")
	t.assertClean()
}

func TestAppLoad_StatefulAttachErrorRollsBack(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	entries := internal.CgroupAttaches()
	t.faults.attach[entries[len(entries)-1].Name] = errWorldAttach

	err := t.App.Load()
	t.Match(err, "bpftool attach")
	t.assertClean()
}

func TestAppLoad_StatefulSuccessMounted(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)

	t.Nil(t.App.Load())
	t.True(t.state.mounted)
	_, err := fs.Stat(t.state.fs, trimRoot(internal.BPFDir))
	t.Nil(err)
	t.assertAttachedAll()
	t.Len(t.state.tempFiles, 0)
}

func TestAppLoad_StatefulSuccessMountFresh(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.mounted = false

	t.Nil(t.App.Load())
	t.True(t.state.mounted)
	_, err := fs.Stat(t.state.fs, trimRoot(internal.BPFDir))
	t.Nil(err)
	t.assertAttachedAll()
}

func TestAppUnload_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.Unload() })
}

func TestAppUnload_StatefulWithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppUnload_StatefulWithBPF(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.fs[trimRoot(internal.BPFDir)] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
	for _, att := range internal.CgroupAttaches() {
		t.state.attached[att.Name] = struct{}{}
	}

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppUnload_StatefulBPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.state.fs[trimRoot(internal.BPFDir)] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
	t.faults.removeAll = errWorldRemove

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_StatefulBPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.stat = errWorldStat

	err := t.App.Unload()
	t.Match(err, "stat BPF pin dir")
	t.Match(err, errWorldStat.Error())
}

func TestAppUnload_StatefulCgroupShowError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.cgroupShow = errWorldBpftool

	err := t.App.Unload()
	t.Match(err, "cannot verify cgroup attachments")
}

func TestAppUnload_StatefulCgroupShowExitCode2(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)

	cmd := exec.Command("sh", "-c", "exit 2") //nolint:noctx // Trivial, exits immediately.
	t.faults.cgroupShow = cmd.Run()

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppUnload_StatefulInvalidJSON(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.cgroupShowRaw = []byte("{")

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppUnload_StatefulCgroupShowNoOutput(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.cgroupShowRaw = []byte{}

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppUnload_StatefulCgroupShowBracketOnly(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.cgroupShowRaw = []byte("[")

	t.Nil(t.App.Unload())
	t.assertClean()
}

func TestAppSetMark_StatefulDoFailures(tt *testing.T) {
	tt.Parallel()
	runDoFailures(tt, func(t *statefulAppTest) error { return t.App.SetMark(internal.Mark(0x10000000)) })
}

func TestAppSetMark_StatefulSuccess(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	mark := internal.Mark(0x10000000)

	t.Nil(t.App.SetMark(mark))
	t.DeepEqual(t.state.markBytes, mark.ToLE())
	t.assertClean()
}

func TestAppSetMark_StatefulError(tt *testing.T) {
	tt.Parallel()
	t := newStatefulAppTest(tt)
	t.faults.mapUpdate = errWorldBpftool

	err := t.App.SetMark(internal.Mark(0x10000000))
	t.Match(err, "bpftool map update")
	t.assertClean()
}
