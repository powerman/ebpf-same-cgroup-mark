package main_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

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

	Ctrl  *gomock.Controller
	World *MockWorld
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
	entries := make([]main.CgroupAttachEntry, 0, len(names))
	for _, name := range names {
		for _, att := range main.CgroupAttach() {
			if att.ProgName == name {
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

	t.Ctrl = gomock.NewController(t)
	t.World = NewMockWorld(t.Ctrl)
	t.state = &worldState{
		euid:      0,
		mounted:   true,
		attached:  make(map[string]struct{}),
		tempFiles: make(map[string]struct{}),
		attachErr: make(map[string]error),
		detachErr: make(map[string]error),
	}
	t.installWorld()
	t.App = main.NewApp(t.World)

	return t
}

func (t *statefulAppTest) installWorld() {
	t.World.EXPECT().OsGeteuid().AnyTimes().DoAndReturn(func() int {
		return t.state.euid
	})
	t.World.EXPECT().OsMkdirAll(main.BPFRoot, main.BPFMode).AnyTimes().DoAndReturn(func(string, os.FileMode) error {
		return t.state.mkdirErr
	})
	t.World.EXPECT().OsRemove(gomock.Any()).AnyTimes().DoAndReturn(func(name string) error {
		delete(t.state.tempFiles, name)
		return t.state.removeErr
	})
	t.World.EXPECT().OsRemoveAll(main.BPFDir).AnyTimes().DoAndReturn(func(string) error {
		if t.state.removeAllErr != nil {
			return t.state.removeAllErr
		}
		t.state.bpfDirExists = false
		return nil
	})
	t.World.EXPECT().OsStat(main.BPFDir).AnyTimes().DoAndReturn(func(string) (os.FileInfo, error) {
		if t.state.statErr != nil {
			return nil, t.state.statErr
		}
		if t.state.bpfDirExists {
			return dummyFileInfo{}, nil
		}
		return nil, os.ErrNotExist
	})
	t.World.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").AnyTimes().DoAndReturn(func(string, string) (main.WorldOsFile, error) {
		if t.state.createTempErr != nil {
			return nil, t.state.createTempErr
		}
		return t.newTempFile(), nil
	})
	t.World.EXPECT().ExecCommand("mountpoint", "-q", main.BPFRoot).AnyTimes().DoAndReturn(func(string, ...string) main.WorldExecCmd {
		return t.newRunCmd(func() error {
			if t.state.mounted {
				return nil
			}
			return errWorldNotMounted
		})
	})
	t.World.EXPECT().ExecCommand("mount", "-t", "bpf", "bpf", main.BPFRoot).AnyTimes().DoAndReturn(func(string, ...string) main.WorldExecCmd {
		return t.newCombinedOutputCmd(func() ([]byte, error) {
			if t.state.mountErr != nil {
				return t.state.mountOutput, t.state.mountErr
			}
			t.state.mounted = true
			return nil, nil
		})
	})
	t.World.EXPECT().ExecCommand(
		"bpftool", "prog", "loadall", gomock.Any(), main.BPFDir, "pinmaps", main.BPFDir+"/maps",
	).AnyTimes().DoAndReturn(func(string, ...string) main.WorldExecCmd {
		return t.newRunCmd(func() error {
			if t.state.loadallErr != nil {
				return t.state.loadallErr
			}
			t.state.bpfDirExists = true
			return nil
		})
	})
	t.World.EXPECT().ExecCommand(
		"bpftool", "cgroup", "attach", main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).AnyTimes().DoAndReturn(func(_ string, args ...string) main.WorldExecCmd {
		return t.newRunCmd(func() error {
			attachType := args[3]
			progPin := args[5]
			progName := filepath.Base(progPin)
			err := t.state.attachErr[progName]
			if err != nil {
				return err
			}
			t.state.bpfDirExists = true
			t.state.attached[progName] = struct{}{}
			_ = attachType
			return nil
		})
	})
	t.World.EXPECT().ExecCommand(
		"bpftool", "cgroup", "detach", main.CgroupRoot, gomock.Any(), "pinned", gomock.Any(),
	).AnyTimes().DoAndReturn(func(_ string, args ...string) main.WorldExecCmd {
		return t.newRunCmd(func() error {
			attachType := args[3]
			progPin := args[5]
			progName := filepath.Base(progPin)
			err := t.state.detachErr[progName]
			if err != nil {
				return err
			}
			delete(t.state.attached, progName)
			_ = attachType
			return nil
		})
	})
	t.World.EXPECT().ExecCommand(
		"bpftool", "map", "update",
		"pinned", main.BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).AnyTimes().DoAndReturn(func(_ string, args ...string) main.WorldExecCmd {
		return t.newRunCmd(func() error {
			if t.state.mapUpdateErr != nil {
				return t.state.mapUpdateErr
			}
			last := len(args) - 4
			t.state.markBytes = [4]string{args[last], args[last+1], args[last+2], args[last+3]}
			return nil
		})
	})
	t.World.EXPECT().ExecCommand("bpftool", "--json", "cgroup", "show", main.CgroupRoot).AnyTimes().DoAndReturn(func(string, ...string) main.WorldExecCmd {
		return t.newOutputOnlyCmd(func() ([]byte, error) {
			if t.state.cgroupShowErr != nil {
				return nil, t.state.cgroupShowErr
			}
			if t.state.cgroupShowRaw != nil {
				return t.state.cgroupShowRaw, nil
			}
			return cgroupShowJSONWorld(t.attachedProgramNames()...), nil
		})
	})
}

func (t *statefulAppTest) newRunCmd(run func() error) main.WorldExecCmd {
	cmd := NewMockWorldExecCmd(t.Ctrl)
	cmd.EXPECT().Run().DoAndReturn(run).Times(1)
	return cmd
}

func (t *statefulAppTest) newCombinedOutputCmd(output func() ([]byte, error)) main.WorldExecCmd {
	cmd := NewMockWorldExecCmd(t.Ctrl)
	cmd.EXPECT().CombinedOutput().DoAndReturn(output).Times(1)
	return cmd
}

func (t *statefulAppTest) newOutputOnlyCmd(output func() ([]byte, error)) main.WorldExecCmd {
	cmd := NewMockWorldExecCmd(t.Ctrl)
	cmd.EXPECT().Output().DoAndReturn(output).Times(1)
	return cmd
}

func (t *statefulAppTest) newTempFile() main.WorldOsFile {
	path := "/tmp/stateful-" + strconv.Itoa(t.state.nextTempID) + ".bpf.o"
	t.state.nextTempID++
	t.state.tempFiles[path] = struct{}{}

	file := NewMockWorldOsFile(t.Ctrl)
	file.EXPECT().Name().AnyTimes().Return(path)
	file.EXPECT().Write(main.BPFObj).DoAndReturn(func([]byte) (int, error) {
		if t.state.tempWriteErr != nil {
			return 0, t.state.tempWriteErr
		}
		return len(main.BPFObj), nil
	}).Times(1)
	file.EXPECT().Close().DoAndReturn(func() error {
		return t.state.tempCloseErr
	}).Times(1)
	return file
}

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
	entries := main.CgroupAttach()
	t.state.attachErr[entries[len(entries)-1].ProgName] = errWorldAttach

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
	for _, att := range main.CgroupAttach() {
		t.state.attached[att.ProgName] = struct{}{}
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
