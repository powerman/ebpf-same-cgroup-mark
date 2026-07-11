package internal_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
	port "github.com/powerman/ebpf-same-cgroup-mark/test/internal"
)

var BPFDir = trimRoot(internal.BPFDir)

var (
	errAttach      = errors.New("stub attach error")
	errBpftool     = errors.New("stub bpftool error")
	errClose       = errors.New("stub close error")
	errLoadall     = errors.New("stub loadall error")
	errMkdir       = errors.New("stub mkdir error")
	errMountFailed = errors.New("stub mount failed error")
	errNotMount    = errors.New("stub not mounted error")
	errRemove      = errors.New("stub remove error")
	errStat        = errors.New("stub stat error")
	errWrite       = errors.New("stub write error")
)

// trimRoot strips the leading "/" from absolute paths
// so they can be used as keys in fstest.MapFS.
func trimRoot(p string) string { return strings.TrimLeft(p, "/") }

// OsFile implements internal.WorldOsFile.
type OsFile struct {
	name  string
	write func([]byte) (int, error)
	close func() error
}

func (f *OsFile) Name() string                { return f.name }
func (f *OsFile) Write(p []byte) (int, error) { return f.write(p) }
func (f *OsFile) Close() error                { return f.close() }

// World implements internal.World with go-mockgen for command
// and OS method dispatch.
type World struct {
	*port.MockStubWorld

	euid      int
	FS        fstest.MapFS
	Mounted   bool
	Attached  []internal.CgroupAttach
	markBytes [4]string

	nextID int
}

func newWorld() *World {
	m := &World{
		MockStubWorld: port.NewMockStubWorld(),
		euid:          0,
		Mounted:       true,
		FS:            make(fstest.MapFS),
	}

	m.MountpointFunc.SetDefaultHook(func(dir string) error {
		if m.Mounted {
			return nil
		}
		return errNotMount
	})

	m.MountBPFFunc.SetDefaultHook(func(fstype, target string) ([]byte, error) {
		m.Mounted = true
		return nil, nil
	})

	m.BpftoolProgLoadAllFunc.SetDefaultHook(func(bpfObjPath, bpffs, mapsDir string) ([]byte, error) {
		m.FS[BPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
		return nil, nil
	})

	m.BpftoolCgroupAttachFunc.SetDefaultHook(func(cgroup, attachType, progPin string) error {
		att := internal.CgroupAttach{Name: filepath.Base(progPin), AttachType: attachType}
		m.Attached = append(m.Attached, att)
		return nil
	})

	m.BpftoolCgroupDetachFunc.SetDefaultHook(func(cgroup, attachType, progPin string) error {
		att := internal.CgroupAttach{Name: filepath.Base(progPin), AttachType: attachType}
		if i := slices.Index(m.Attached, att); i != -1 {
			m.Attached = slices.Delete(m.Attached, i, i+1)
		}
		return nil
	})

	m.BpftoolMapUpdateFunc.SetDefaultHook(func(args ...string) error {
		last := len(args) - 4
		m.markBytes = [4]string{args[last], args[last+1], args[last+2], args[last+3]}
		return nil
	})

	m.BpftoolCgroupShowFunc.SetDefaultHook(func(cgroup string) ([]byte, error) {
		return json.Marshal(m.Attached)
	})

	m.OsCreateTempFunc.SetDefaultHook(func(dir, pattern string) (internal.WorldOsFile, error) {
		path := fmt.Sprintf("tmp/stub-%d.bpf.o", m.nextID)
		m.nextID++
		m.FS[path] = &fstest.MapFile{Mode: 0o600}
		return &OsFile{
			name: path,
			write: func(data []byte) (int, error) {
				m.FS[path].Data = append(m.FS[path].Data, data...)
				return len(data), nil
			},
			close: func() error { return nil },
		}, nil
	})

	m.OsGeteuidFunc.SetDefaultHook(func() int {
		return m.euid
	})

	m.OsMkdirAllFunc.SetDefaultHook(func(path string, perm os.FileMode) error {
		m.FS[trimRoot(path)] = &fstest.MapFile{Mode: os.ModeDir | perm}
		return nil
	})

	m.OsRemoveFunc.SetDefaultHook(func(name string) error {
		delete(m.FS, trimRoot(name))
		return nil
	})

	m.OsRemoveAllFunc.SetDefaultHook(func(path string) error {
		paths, _ := fs.Glob(m.FS, trimRoot(path)+"/*")
		for _, f := range append(paths, trimRoot(path)) {
			delete(m.FS, f)
		}
		return nil
	})

	m.OsStatFunc.SetDefaultHook(func(name string) (os.FileInfo, error) {
		return fs.Stat(m.FS, trimRoot(name))
	})

	return m
}

type AppTest struct {
	*check.TB

	World *World
	App   internal.App
}

func newAppTest(tt *testing.T) *AppTest {
	tt.Helper()
	t := &AppTest{TB: check.Must(tt)}
	t.World = newWorld()
	t.App = internal.NewApp(t.World, []byte("test-bpf-object"))
	return t
}

func (t *AppTest) AssertNoTempFiles() {
	t.Helper()
	names, _ := fs.Glob(t.World.FS, "tmp/*")
	t.Zero(names)
}

func (t *AppTest) AssertClean() {
	t.Helper()
	t.Len(t.World.Attached, 0)
	t.AssertNoTempFiles()
	_, err := fs.Stat(t.World.FS, BPFDir)
	t.Err(err, fs.ErrNotExist, "expected BPF dir to not exist")
}

// testDoFailures tests the shared do() failure paths across Load/Unload/SetMark.
func testDoFailures(t *testing.T, f func(t *AppTest) error) {
	t.Helper()
	t.Parallel()

	t.Run("RootCheckError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.OsGeteuidFunc.PushReturn(1000)
		t.Err(f(t), internal.ErrMustBeRoot)
	})

	t.Run("EnsureBPFFSMkdirError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.Mounted = false
		t.World.OsMkdirAllFunc.PushReturn(errMkdir)
		t.Err(f(t), errMkdir)
	})

	t.Run("EnsureBPFFSMountError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.Mounted = false
		t.World.MountpointFunc.PushReturn(errNotMount)
		t.World.MountBPFFunc.PushReturn([]byte("mount failure details"), errMountFailed)
		t.Err(f(t), errMountFailed)
	})
}

func TestAppLoad_DoErrors(tt *testing.T) {
	testDoFailures(tt, func(t *AppTest) error { return t.App.Load() })
}

func TestAppLoad_WriteTempErrors(t *testing.T) {
	t.Parallel()

	t.Run("CreateError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.OsCreateTempFunc.PushReturn(nil, errMkdir)
		err := t.App.Load()
		t.Err(err, errMkdir)
		t.AssertClean()
	})

	t.Run("WriteError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.OsCreateTempFunc.PushReturn(&OsFile{
			name:  "tmp/test.bpf.o",
			write: func(_ []byte) (int, error) { return 0, errWrite },
			close: func() error { return nil },
		}, nil)
		err := t.App.Load()
		t.Err(err, errWrite)
		t.AssertClean()
	})

	t.Run("CloseError", func(tt *testing.T) {
		tt.Parallel()
		t := newAppTest(tt)
		t.World.OsCreateTempFunc.PushReturn(&OsFile{
			name:  "tmp/test.bpf.o",
			write: func(data []byte) (int, error) { return len(data), nil },
			close: func() error { return errClose },
		}, nil)
		err := t.App.Load()
		t.Err(err, errClose)
		t.AssertClean()
	})
}

func TestAppLoad_CleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	// Simulate previous Load state.
	t.World.BpftoolProgLoadAll("fake.bpf.o", internal.BPFDir, internal.BPFDir+"/maps")
	t.World.BpftoolCgroupAttach(internal.CgroupRoot, "cgroup_inet4_bind", internal.BPFDir+"/same_cgroup_bind4")

	t.World.BpftoolCgroupDetachFunc.PushReturn(errRemove)

	err := t.App.Load()
	t.Match(err, "cleanup previous state: BPF program still attached to cgroup: same_cgroup_bind4")
}

func TestAppLoad_LoadallError(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	t.World.BpftoolProgLoadAllFunc.PushReturn(nil, errLoadall)

	err := t.App.Load()
	t.Err(err, errLoadall)
	t.AssertClean()
}

func TestAppLoad_AttachErrorRollsBack(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	for range len(internal.CgroupAttaches()) - 1 {
		t.World.BpftoolCgroupAttachFunc.PushReturn(nil)
	}
	t.World.BpftoolCgroupAttachFunc.PushReturn(errAttach)

	err := t.App.Load()
	t.Err(err, errAttach)
	t.AssertClean()
}

func TestAppLoad_Mounted(t *testing.T) {
	t.Parallel()

	for _, tc := range []bool{false, true} {
		t.Run(fmt.Sprintf("Mounted=%t", tc), func(tt *testing.T) {
			tt.Parallel()
			t := newAppTest(tt)

			t.World.Mounted = tc

			t.Nil(t.App.Load())
			t.True(t.World.Mounted)
			_, err := fs.Stat(t.World.FS, BPFDir)
			t.Nil(err)
			t.DeepEqual(t.World.Attached, internal.CgroupAttaches())
			t.AssertNoTempFiles()
		})
	}
}

func TestAppUnload_DoErrors(tt *testing.T) {
	testDoFailures(tt, func(t *AppTest) error { return t.App.Unload() })
}

func TestAppUnload_WithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_WithBPF(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)
	t.World.BpftoolProgLoadAll("fake.bpf.o", internal.BPFDir, internal.BPFDir+"/maps")
	for _, att := range internal.CgroupAttaches() {
		t.World.BpftoolCgroupAttach(internal.CgroupRoot, att.AttachType, internal.BPFDir+"/"+att.Name)
	}

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_BPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)
	t.World.FS[BPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}

	t.World.OsRemoveAllFunc.PushReturn(errRemove)

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_BPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	t.World.OsStatFunc.PushReturn(nil, errStat)

	err := t.App.Unload()
	t.Err(err, errStat)
}

func TestAppUnload_CgroupShow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ret     []byte
		retErr  error
		wantErr string
	}{
		{name: "NoOutput", ret: []byte{}},
		{name: "BracketOnly", ret: []byte("[")},
		{name: "InvalidJSON", ret: []byte("{")},
		{name: "ExitCode1", retErr: exec.Command("false").Run(), wantErr: "cannot verify cgroup attachments"},
		{name: "ExitCode2", retErr: exec.Command("sh", "-c", "exit 2").Run()},
		{name: "Error", retErr: errBpftool, wantErr: "cannot verify cgroup attachments"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := newAppTest(tt)
			t.World.BpftoolCgroupShowFunc.PushReturn(tc.ret, tc.retErr)
			err := t.App.Unload()
			if tc.wantErr != "" {
				t.Match(err, tc.wantErr)
			} else {
				t.Nil(err)
			}
		})
	}
}

func TestAppSetMark_DoErrors(tt *testing.T) {
	testDoFailures(tt, func(t *AppTest) error { return t.App.SetMark(internal.Mark(0x10000000)) })
}

func TestAppSetMark_Success(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)
	mark := internal.Mark(0x10000000)

	t.Nil(t.App.SetMark(mark))
	t.DeepEqual(t.World.markBytes, mark.ToLE())
}

func TestAppSetMark_Error(tt *testing.T) {
	tt.Parallel()
	t := newAppTest(tt)

	t.World.BpftoolMapUpdateFunc.PushReturn(errBpftool)

	err := t.App.SetMark(internal.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
