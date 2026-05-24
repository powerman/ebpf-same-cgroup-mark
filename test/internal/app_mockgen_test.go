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
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gobwas/glob"
	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
)

var mockgenBPFDir = mockgenTrimRoot(internal.BPFDir)

var (
	errMockgenAttach      = errors.New("mockgen attach error")
	errMockgenBpftool     = errors.New("mockgen bpftool error")
	errMockgenClose       = errors.New("mockgen close error")
	errMockgenLoadall     = errors.New("mockgen loadall error")
	errMockgenMkdir       = errors.New("mockgen mkdir error")
	errMockgenMountFailed = errors.New("mockgen mount failed error")
	errMockgenNotMount    = errors.New("mockgen not mounted error")
	errMockgenRemove      = errors.New("mockgen remove error")
	errMockgenStat        = errors.New("mockgen stat error")
	errMockgenWrite       = errors.New("mockgen write error")
)

// mockgenTrimRoot strips the leading "/" from absolute paths
// so they can be used as keys in fstest.MapFS.
func mockgenTrimRoot(p string) string { return strings.TrimLeft(p, "/") }

// mockgenExecCmd implements internal.WorldExecCmd.
type mockgenExecCmd struct {
	run            func() error
	combinedOutput func() ([]byte, error)
	output         func() ([]byte, error)
}

func (c *mockgenExecCmd) Run() error {
	if c.run == nil {
		panic("unexpected call to Run()")
	}
	return c.run()
}

func (c *mockgenExecCmd) CombinedOutput() ([]byte, error) {
	if c.combinedOutput == nil {
		panic("unexpected call to CombinedOutput()")
	}
	return c.combinedOutput()
}

func (c *mockgenExecCmd) Output() ([]byte, error) {
	if c.output == nil {
		panic("unexpected call to Output()")
	}
	return c.output()
}

// mockgenOsFile implements internal.WorldOsFile.
type mockgenOsFile struct {
	name  string
	write func([]byte) (int, error)
	close func() error
}

func (f *mockgenOsFile) Name() string                { return f.name }
func (f *mockgenOsFile) Write(p []byte) (int, error) { return f.write(p) }
func (f *mockgenOsFile) Close() error                { return f.close() }

// mockgenMockgenWorld implements internal.World with go-mockgen for command
// and OS method dispatch.
type mockgenMockgenWorld struct {
	*MockgenWorld
	Cmds *MockWorldCmds

	euid      int
	FS        fstest.MapFS
	Mounted   bool
	Attached  []internal.CgroupAttach
	markBytes [4]string

	nextID int
}

func newMockgenWorld() *mockgenMockgenWorld {
	m := &mockgenMockgenWorld{
		MockgenWorld: NewMockgenWorld(),
		euid:         0,
		Mounted:      true,
		FS:           make(fstest.MapFS),
	}
	m.Cmds = NewMockWorldCmds()

	m.Cmds.MountpointFunc.SetDefaultHook(func(dir string) error {
		if m.Mounted {
			return nil
		}
		return errMockgenNotMount
	})

	m.Cmds.MountBPFFunc.SetDefaultHook(func(fstype, target string) ([]byte, error) {
		m.Mounted = true
		return nil, nil
	})

	m.Cmds.BpftoolProgLoadAllFunc.SetDefaultHook(func(bpfObjPath, bpffs, mapsDir string) ([]byte, error) {
		m.FS[mockgenBPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
		return nil, nil
	})

	m.Cmds.BpftoolCgroupAttachFunc.SetDefaultHook(func(cgroup, attachType, progPin string) error {
		att := internal.CgroupAttach{Name: filepath.Base(progPin), AttachType: attachType}
		m.Attached = append(m.Attached, att)
		return nil
	})

	m.Cmds.BpftoolCgroupDetachFunc.SetDefaultHook(func(cgroup, attachType, progPin string) error {
		att := internal.CgroupAttach{Name: filepath.Base(progPin), AttachType: attachType}
		if i := slices.Index(m.Attached, att); i != -1 {
			m.Attached = slices.Delete(m.Attached, i, i+1)
		}
		return nil
	})

	m.Cmds.BpftoolMapUpdateFunc.SetDefaultHook(func(args ...string) error {
		last := len(args) - 4
		m.markBytes = [4]string{args[last], args[last+1], args[last+2], args[last+3]}
		return nil
	})

	m.Cmds.BpftoolCgroupShowFunc.SetDefaultHook(func(cgroup string) ([]byte, error) {
		out, _ := json.Marshal(m.Attached)
		return out, nil
	})

	m.OsCreateTempFunc.SetDefaultHook(func(dir, pattern string) (internal.WorldOsFile, error) {
		path := "tmp/mockgen-" + strconv.Itoa(m.nextID) + ".bpf.o"
		m.nextID++
		m.FS[path] = &fstest.MapFile{Mode: 0o600}
		return &mockgenOsFile{
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
		m.FS[mockgenTrimRoot(path)] = &fstest.MapFile{Mode: os.ModeDir | perm}
		return nil
	})

	m.OsRemoveFunc.SetDefaultHook(func(name string) error {
		delete(m.FS, mockgenTrimRoot(name))
		return nil
	})

	m.OsRemoveAllFunc.SetDefaultHook(func(path string) error {
		entries, _ := fs.Glob(m.FS, mockgenTrimRoot(path)+"/*")
		for _, f := range append(entries, mockgenTrimRoot(path)) {
			delete(m.FS, f)
		}
		return nil
	})

	m.OsStatFunc.SetDefaultHook(func(name string) (os.FileInfo, error) {
		return fs.Stat(m.FS, mockgenTrimRoot(name))
	})

	return m
}

// ExecCommand dispatches to typed go-mockgen methods via command-line matching.
// Each command's effect is deferred to the run/Output/CombinedOutput closure.
func (m *mockgenMockgenWorld) ExecCommand(name string, args ...string) internal.WorldExecCmd {
	cmdline := name + " " + strings.Join(args, " ")
	switch {
	case cmdline == "mountpoint -q "+internal.BPFRoot:
		return &mockgenExecCmd{
			run: func() error { return m.Cmds.Mountpoint(internal.BPFRoot) },
		}

	case cmdline == "mount -t bpf bpf "+internal.BPFRoot:
		return &mockgenExecCmd{
			combinedOutput: func() ([]byte, error) { return m.Cmds.MountBPF("bpf", internal.BPFRoot) },
		}

	case glob.MustCompile("bpftool prog loadall * "+internal.BPFDir+" pinmaps "+internal.BPFDir+"/maps", ' ').Match(cmdline):
		return &mockgenExecCmd{
			combinedOutput: func() ([]byte, error) {
				out, err := m.Cmds.BpftoolProgLoadAll(args[2], args[3], args[5])
				return out, err
			},
		}

	case glob.MustCompile("bpftool cgroup attach "+internal.CgroupRoot+" * pinned *", ' ').Match(cmdline):
		return &mockgenExecCmd{
			run: func() error { return m.Cmds.BpftoolCgroupAttach(args[2], args[3], args[5]) },
		}

	case glob.MustCompile("bpftool cgroup detach "+internal.CgroupRoot+" * pinned *", ' ').Match(cmdline):
		return &mockgenExecCmd{
			run: func() error { return m.Cmds.BpftoolCgroupDetach(args[2], args[3], args[5]) },
		}

	case glob.MustCompile("bpftool map update pinned "+internal.BPFDir+"/maps/same_cgroup_mark_cfg key hex 00 00 00 00 value hex * * * *", ' ').Match(cmdline):
		return &mockgenExecCmd{
			run: func() error { return m.Cmds.BpftoolMapUpdate(args...) },
		}

	case cmdline == "bpftool --json cgroup show "+internal.CgroupRoot:
		return &mockgenExecCmd{
			output: func() ([]byte, error) { return m.Cmds.BpftoolCgroupShow(internal.CgroupRoot) },
		}

	default:
		panic(fmt.Sprintf("unexpected command: %s", cmdline))
	}
}

type mockgenAppTest struct {
	*check.C

	World *mockgenMockgenWorld
	App   internal.App
}

func newMockgenAppTest(tt *testing.T) *mockgenAppTest {
	tt.Helper()
	t := &mockgenAppTest{C: check.T(tt).MustAll()}
	t.World = newMockgenWorld()
	t.App = internal.NewApp(t.World, []byte("test-bpf-object"))
	return t
}

func (t *mockgenAppTest) assertNoTempFiles() {
	t.Helper()
	names, _ := fs.Glob(t.World.FS, "tmp/*")
	t.Zero(names)
}

func (t *mockgenAppTest) AssertClean() {
	t.Helper()
	t.Len(t.World.Attached, 0)
	t.assertNoTempFiles()
	_, err := fs.Stat(t.World.FS, mockgenBPFDir)
	t.Err(err, fs.ErrNotExist, "expected BPF dir to not exist")
}

// mockgenRunDoFailures tests the shared do() failure paths
// across Load/Unload/SetMark.
func mockgenRunDoFailures(tt *testing.T, f func(t *mockgenAppTest) error) {
	tt.Helper()
	tt.Parallel()

	tt.Run("RootCheckError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.OsGeteuidFunc.PushReturn(1000)
		t.Err(f(t), internal.ErrMustBeRoot)
	})

	tt.Run("EnsureBPFFSMkdirError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.Mounted = false
		t.World.OsMkdirAllFunc.PushReturn(errMockgenMkdir)
		t.Err(f(t), errMockgenMkdir)
	})

	tt.Run("EnsureBPFFSMountError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.Mounted = false
		t.World.Cmds.MountpointFunc.PushReturn(errMockgenNotMount)
		t.World.Cmds.MountBPFFunc.PushReturn([]byte("mount failure details"), errMockgenMountFailed)
		t.Err(f(t), errMockgenMountFailed)
	})
}

// --- Load tests ---

func TestAppLoad_MockgenDoErrors(tt *testing.T) {
	mockgenRunDoFailures(tt, func(t *mockgenAppTest) error { return t.App.Load() })
}

func TestAppLoad_MockgenWriteTempErrors(tt *testing.T) {
	tt.Parallel()

	tt.Run("CreateError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.OsCreateTempFunc.PushReturn(nil, errMockgenMkdir)
		err := t.App.Load()
		t.Err(err, errMockgenMkdir)
		t.AssertClean()
	})

	tt.Run("WriteError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.OsCreateTempFunc.PushHook(func(_, _ string) (internal.WorldOsFile, error) {
			return &mockgenOsFile{
				name:  "tmp/test.bpf.o",
				write: func(_ []byte) (int, error) { return 0, errMockgenWrite },
				close: func() error { return nil },
			}, nil
		})
		err := t.App.Load()
		t.Err(err, errMockgenWrite)
		t.AssertClean()
	})

	tt.Run("CloseError", func(tt *testing.T) {
		tt.Parallel()
		t := newMockgenAppTest(tt)
		t.World.OsCreateTempFunc.PushHook(func(_, _ string) (internal.WorldOsFile, error) {
			return &mockgenOsFile{
				name:  "tmp/test.bpf.o",
				write: func(data []byte) (int, error) { return len(data), nil },
				close: func() error { return errMockgenClose },
			}, nil
		})
		err := t.App.Load()
		t.Err(err, errMockgenClose)
		t.AssertClean()
	})
}

func TestAppLoad_MockgenCleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	// Simulate previous Load state.
	t.World.ExecCommand("bpftool", "prog", "loadall", "fake.bpf.o",
		internal.BPFDir, "pinmaps", internal.BPFDir+"/maps").CombinedOutput()
	t.World.ExecCommand("bpftool", "cgroup", "attach", internal.CgroupRoot,
		"cgroup_inet4_bind", "pinned", internal.BPFDir+"/same_cgroup_bind4").Run()

	t.World.Cmds.BpftoolCgroupDetachFunc.PushReturn(errMockgenRemove)

	err := t.App.Load()
	t.Match(err, "cleanup previous state: BPF program still attached to cgroup: same_cgroup_bind4")
}

func TestAppLoad_MockgenLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	t.World.Cmds.BpftoolProgLoadAllFunc.PushReturn(nil, errMockgenLoadall)

	err := t.App.Load()
	t.Err(err, errMockgenLoadall)
	t.AssertClean()
}

func TestAppLoad_MockgenAttachErrorRollsBack(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	for range len(internal.CgroupAttaches()) - 1 {
		t.World.Cmds.BpftoolCgroupAttachFunc.PushReturn(nil)
	}
	t.World.Cmds.BpftoolCgroupAttachFunc.PushReturn(errMockgenAttach)

	err := t.App.Load()
	t.Err(err, errMockgenAttach)
	t.AssertClean()
}

func TestAppLoad_MockgenMounted(tt *testing.T) {
	tt.Parallel()

	for _, tc := range []bool{false, true} {
		tt.Run(fmt.Sprintf("Mounted=%t", tc), func(tt *testing.T) {
			tt.Parallel()
			t := newMockgenAppTest(tt)

			t.World.Mounted = tc

			t.Nil(t.App.Load())
			t.True(t.World.Mounted)
			_, err := fs.Stat(t.World.FS, mockgenBPFDir)
			t.Nil(err)
			t.DeepEqual(t.World.Attached, internal.CgroupAttaches())
			t.assertNoTempFiles()
		})
	}
}

// --- Unload tests ---

func TestAppUnload_MockgenDoErrors(tt *testing.T) {
	mockgenRunDoFailures(tt, func(t *mockgenAppTest) error { return t.App.Unload() })
}

func TestAppUnload_MockgenWithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_MockgenWithBPF(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)
	t.World.ExecCommand("bpftool", "prog", "loadall", "fake.bpf.o",
		internal.BPFDir, "pinmaps", internal.BPFDir+"/maps").CombinedOutput()
	for _, att := range internal.CgroupAttaches() {
		t.World.ExecCommand("bpftool", "cgroup", "attach", internal.CgroupRoot,
			att.AttachType, "pinned", internal.BPFDir+"/"+att.Name).Run()
	}

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_MockgenBPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)
	t.World.FS[mockgenBPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}

	t.World.OsRemoveAllFunc.PushReturn(errMockgenRemove)

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_MockgenBPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	t.World.OsStatFunc.PushReturn(nil, errMockgenStat)

	err := t.App.Unload()
	t.Err(err, errMockgenStat)
}

func TestAppUnload_MockgenCgroupShow(t *testing.T) {
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
		{name: "Error", retErr: errMockgenBpftool, wantErr: "cannot verify cgroup attachments"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := newMockgenAppTest(tt)
			t.World.Cmds.BpftoolCgroupShowFunc.PushReturn(tc.ret, tc.retErr)
			err := t.App.Unload()
			if tc.wantErr != "" {
				t.Match(err, tc.wantErr)
			} else {
				t.Nil(err)
			}
		})
	}
}

// --- SetMark tests ---

func TestAppSetMark_MockgenDoErrors(tt *testing.T) {
	mockgenRunDoFailures(tt, func(t *mockgenAppTest) error {
		return t.App.SetMark(internal.Mark(0x10000000))
	})
}

func TestAppSetMark_MockgenSuccess(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)
	mark := internal.Mark(0x10000000)

	t.Nil(t.App.SetMark(mark))
	t.DeepEqual(t.World.markBytes, mark.ToLE())
}

func TestAppSetMark_MockgenError(tt *testing.T) {
	tt.Parallel()
	t := newMockgenAppTest(tt)

	t.World.Cmds.BpftoolMapUpdateFunc.PushReturn(errMockgenBpftool)

	err := t.App.SetMark(internal.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
