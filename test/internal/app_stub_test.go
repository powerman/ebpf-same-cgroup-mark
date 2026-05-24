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

	"github.com/gobwas/glob"
	"github.com/powerman/check"

	"github.com/powerman/ebpf-same-cgroup-mark/internal"
	"github.com/powerman/ebpf-same-cgroup-mark/test/stub"
)

var BPFDir = trimRoot(internal.BPFDir)

// errStub* sentinel errors for stub-based tests.
var (
	errStubAttach      = errors.New("stub attach error")
	errStubBpftool     = errors.New("stub bpftool error")
	errStubClose       = errors.New("stub close error")
	errStubLoadall     = errors.New("stub loadall error")
	errStubMkdir       = errors.New("stub mkdir error")
	errStubMountFailed = errors.New("stub mount failed error")
	errStubNotMounted  = errors.New("stub not mounted error")
	errStubRemove      = errors.New("stub remove error")
	errStubStat        = errors.New("stub stat error")
	errStubWrite       = errors.New("stub write error")
)

// stubExecCmd implements internal.WorldExecCmd.
type stubExecCmd struct {
	run            func() error
	combinedOutput func() ([]byte, error)
	output         func() ([]byte, error)
}

func (c *stubExecCmd) Run() error {
	if c.run == nil {
		panic("unexpected call to Run()")
	}
	return c.run()
}

func (c *stubExecCmd) CombinedOutput() ([]byte, error) {
	if c.combinedOutput == nil {
		panic("unexpected call to CombinedOutput()")
	}
	return c.combinedOutput()
}

func (c *stubExecCmd) Output() ([]byte, error) {
	if c.output == nil {
		panic("unexpected call to Output()")
	}
	return c.output()
}

// stubOsFile implements internal.WorldOsFile.
type stubOsFile struct {
	name  string
	write func([]byte) (int, error)
	close func() error
}

func (f *stubOsFile) Name() string                { return f.name }
func (f *stubOsFile) Write(p []byte) (int, error) { return f.write(p) }
func (f *stubOsFile) Close() error                { return f.close() }

// stubWorld implements internal.World with per-command stubs.
type stubWorld struct {
	euid      int
	FS        fstest.MapFS
	Mounted   bool
	Attached  []internal.CgroupAttach
	markBytes [4]string

	nextID int

	Stub struct {
		ExecMountpoint        stub.Res[bool]
		ExecMount             stub.ResErr[[]byte]
		ExecBpftoolLoadall    stub.Err
		ExecBpftoolAttach     stub.Err
		ExecBpftoolDetach     stub.Err
		ExecBpftoolMapUpdate  stub.Err
		ExecBpftoolCgroupShow stub.ResErr[[]byte]
		OsCreateTemp          stub.ResErr[internal.WorldOsFile]
		OsGeteuid             stub.Res[int]
		OsMkdirAll            stub.Err
		OsRemove              stub.Err
		OsRemoveAll           stub.Err
		OsStat                stub.ResErr[os.FileInfo]
	}
}

func newStubWorld() *stubWorld {
	m := &stubWorld{
		euid:    0,
		Mounted: true,
		FS:      make(fstest.MapFS),
	}

	m.Stub.ExecMountpoint = stub.NewRes[bool](func() bool {
		return m.Mounted
	})

	m.Stub.ExecMount = stub.NewResErr[[]byte](func() ([]byte, error) {
		m.Mounted = true
		return nil, nil
	})

	m.Stub.ExecBpftoolLoadall = stub.NewErr(func(_ string) error {
		m.FS[BPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}
		return nil
	})

	m.Stub.ExecBpftoolAttach = stub.NewErr(func(att internal.CgroupAttach) error {
		m.Attached = append(m.Attached, att)
		return nil
	})

	m.Stub.ExecBpftoolDetach = stub.NewErr(func(att internal.CgroupAttach) error {
		if i := slices.Index(m.Attached, att); i != -1 {
			m.Attached = slices.Delete(m.Attached, i, i+1)
		}
		return nil
	})

	m.Stub.ExecBpftoolMapUpdate = stub.NewErr(func(leBytes [4]string) error {
		m.markBytes = leBytes
		return nil
	})

	m.Stub.ExecBpftoolCgroupShow = stub.NewResErr[[]byte](func() ([]byte, error) {
		return json.Marshal(m.Attached)
	})

	m.Stub.OsCreateTemp = stub.NewResErr[internal.WorldOsFile](func(_, _ string) (internal.WorldOsFile, error) {
		path := fmt.Sprintf("tmp/stub-%d.bpf.o", m.nextID)
		m.nextID++
		m.FS[path] = &fstest.MapFile{Mode: 0o600}
		return &stubOsFile{
			name: path,
			write: func(data []byte) (int, error) {
				m.FS[path].Data = append(m.FS[path].Data, data...)
				return len(data), nil
			},
			close: func() error { return nil },
		}, nil
	})

	m.Stub.OsGeteuid = stub.NewRes[int](func() int {
		return m.euid
	})

	m.Stub.OsMkdirAll = stub.NewErr(func(path string, perm os.FileMode) error {
		m.FS[trimRoot(path)] = &fstest.MapFile{Mode: os.ModeDir | perm}
		return nil
	})

	m.Stub.OsRemove = stub.NewErr(func(name string) error {
		delete(m.FS, trimRoot(name))
		return nil
	})

	m.Stub.OsRemoveAll = stub.NewErr(func(path string) error {
		files, _ := fs.Glob(m.FS, trimRoot(path)+"/*")
		for _, f := range append(files, trimRoot(path)) {
			delete(m.FS, f)
		}
		return nil
	})

	m.Stub.OsStat = stub.NewResErr[os.FileInfo](func(name string) (os.FileInfo, error) {
		return fs.Stat(m.FS, trimRoot(name))
	})

	return m
}

// ExecCommand dispatches to per-command stubs and wraps the result in a stubCmd.
func (m *stubWorld) ExecCommand(name string, args ...string) internal.WorldExecCmd {
	cmdline := strings.Join(append([]string{name}, args...), " ")
	switch {
	case cmdline == "mountpoint -q /sys/fs/bpf":
		return &stubExecCmd{
			run: func() error {
				if m.Stub.ExecMountpoint.Call() {
					return nil
				}
				return errStubNotMounted
			},
		}

	case cmdline == "mount -t bpf bpf /sys/fs/bpf":
		return &stubExecCmd{
			combinedOutput: func() ([]byte, error) { return m.Stub.ExecMount.Call() },
		}

	case glob.MustCompile("bpftool prog loadall * /sys/fs/bpf/same-cgroup-mark pinmaps /sys/fs/bpf/same-cgroup-mark/maps", ' ').Match(cmdline):
		return &stubExecCmd{
			combinedOutput: func() ([]byte, error) {
				err := m.Stub.ExecBpftoolLoadall.Call(args[2])
				return nil, err
			},
		}

	case glob.MustCompile("bpftool cgroup attach /sys/fs/cgroup * pinned *", ' ').Match(cmdline):
		return &stubExecCmd{
			run: func() error {
				att := internal.CgroupAttach{Name: filepath.Base(args[5]), AttachType: args[3]}
				return m.Stub.ExecBpftoolAttach.Call(att)
			},
		}

	case glob.MustCompile("bpftool cgroup detach /sys/fs/cgroup * pinned *", ' ').Match(cmdline):
		return &stubExecCmd{
			run: func() error {
				att := internal.CgroupAttach{Name: filepath.Base(args[5]), AttachType: args[3]}
				return m.Stub.ExecBpftoolDetach.Call(att)
			},
		}

	case glob.MustCompile("bpftool map update pinned /sys/fs/bpf/same-cgroup-mark/maps/same_cgroup_mark_cfg key hex 00 00 00 00 value hex * * * *", ' ').Match(cmdline):
		return &stubExecCmd{
			run: func() error {
				last := len(args) - 4
				leBytes := [4]string{args[last], args[last+1], args[last+2], args[last+3]}
				return m.Stub.ExecBpftoolMapUpdate.Call(leBytes)
			},
		}

	case cmdline == "bpftool --json cgroup show /sys/fs/cgroup":
		return &stubExecCmd{
			output: func() ([]byte, error) {
				return m.Stub.ExecBpftoolCgroupShow.Call()
			},
		}

	default:
		panic(fmt.Sprintf("unexpected command: %s", cmdline))
	}
}

func (m *stubWorld) OsCreateTemp(dir, pattern string) (internal.WorldOsFile, error) {
	return m.Stub.OsCreateTemp.Call(dir, pattern)
}

func (m *stubWorld) OsGeteuid() int {
	return m.Stub.OsGeteuid.Call()
}

func (m *stubWorld) OsMkdirAll(path string, perm os.FileMode) error {
	return m.Stub.OsMkdirAll.Call(path, perm)
}

func (m *stubWorld) OsRemove(name string) error {
	return m.Stub.OsRemove.Call(name)
}

func (m *stubWorld) OsRemoveAll(path string) error {
	return m.Stub.OsRemoveAll.Call(path)
}

func (m *stubWorld) OsStat(name string) (os.FileInfo, error) {
	return m.Stub.OsStat.Call(name)
}

type stubAppTest struct {
	*check.C

	World *stubWorld
	App   internal.App
}

func newStubAppTest(tt *testing.T) *stubAppTest {
	tt.Helper()
	t := &stubAppTest{C: check.T(tt).MustAll()}
	t.World = newStubWorld()
	t.App = internal.NewApp(t.World, testBPFObj)
	return t
}

func (t *stubAppTest) AssertNoTempFiles() {
	t.Helper()
	names, _ := fs.Glob(t.World.FS, "tmp/*")
	t.Zero(names)
}

func (t *stubAppTest) AssertClean() {
	t.Helper()
	t.Len(t.World.Attached, 0)
	t.AssertNoTempFiles()
	_, err := fs.Stat(t.World.FS, BPFDir)
	t.Err(err, fs.ErrNotExist, "expected BPF dir to not exist")
}

// testDoErrors tests the shared do() failure paths across Load/Unload/SetMark.
func testDoErrors(t *testing.T, f func(t *stubAppTest) error) {
	t.Helper()
	t.Parallel()

	t.Run("RootCheckError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Stub.OsGeteuid.Returns(1000)
		t.Err(f(t), internal.ErrMustBeRoot)
	})

	t.Run("EnsureBPFFSMkdirError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Mounted = false
		t.World.Stub.OsMkdirAll.Fail(errStubMkdir)
		t.Err(f(t), errStubMkdir)
	})

	t.Run("EnsureBPFFSMountError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Mounted = false
		t.World.Stub.ExecMountpoint.Returns(false)
		t.World.Stub.OsMkdirAll.Default()
		t.World.Stub.ExecMount.Fail(errStubMountFailed)
		t.Err(f(t), errStubMountFailed)
	})
}

func TestAppLoad_StubDoErrors(t *testing.T) {
	testDoErrors(t, func(t *stubAppTest) error { return t.App.Load() })
}

func TestAppLoad_StubWriteTempErrors(t *testing.T) {
	t.Parallel()

	t.Run("CreateError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Stub.OsCreateTemp.Fail(errStubMkdir)
		err := t.App.Load()
		t.Err(err, errStubMkdir)
		t.AssertClean()
	})

	t.Run("WriteError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Stub.OsCreateTemp.Returns(&stubOsFile{
			name:  "tmp/test.bpf.o",
			write: func(_ []byte) (int, error) { return 0, errStubWrite },
			close: func() error { return nil },
		}, nil)
		err := t.App.Load()
		t.Err(err, errStubWrite)
		t.AssertClean()
	})

	t.Run("CloseError", func(tt *testing.T) {
		tt.Parallel()
		t := newStubAppTest(tt)
		t.World.Stub.OsCreateTemp.Returns(&stubOsFile{
			name:  "tmp/test.bpf.o",
			write: func(data []byte) (int, error) { return len(data), nil },
			close: func() error { return errStubClose },
		}, nil)
		err := t.App.Load()
		t.Err(err, errStubClose)
		t.AssertClean()
	})
}

func TestAppLoad_StubCleanupPreviousStateError(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)
	t.World.ExecCommand("bpftool", "prog", "loadall", "fake.bpf.o", "/sys/fs/bpf/same-cgroup-mark", "pinmaps", "/sys/fs/bpf/same-cgroup-mark/maps").CombinedOutput()
	t.World.ExecCommand("bpftool", "cgroup", "attach", "/sys/fs/cgroup", "cgroup_inet4_bind", "pinned", "/sys/fs/bpf/same-cgroup-mark/same_cgroup_bind4").Run()

	t.World.Stub.ExecBpftoolDetach.Fail(errStubRemove)

	err := t.App.Load()
	t.Match(err, "cleanup previous state: BPF program still attached to cgroup: same_cgroup_bind4")
}

func TestAppLoad_StubLoadallError(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)

	t.World.Stub.ExecBpftoolLoadall.Fail(errStubLoadall)

	err := t.App.Load()
	t.Err(err, errStubLoadall)
	t.AssertClean()
}

func TestAppLoad_StubAttachErrorRollsBack(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)

	for range len(internal.CgroupAttaches()) - 1 {
		t.World.Stub.ExecBpftoolAttach.Default()
	}
	t.World.Stub.ExecBpftoolAttach.Fail(errStubAttach)

	err := t.App.Load()
	t.Err(err, errStubAttach)
	t.AssertClean()
}

func TestAppLoad_StubMounted(t *testing.T) {
	t.Parallel()

	for _, tc := range []bool{false, true} {
		t.Run(fmt.Sprintf("Mounted=%t", tc), func(tt *testing.T) {
			tt.Parallel()
			t := newStubAppTest(tt)

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

func TestAppUnload_StubDoErrors(t *testing.T) {
	testDoErrors(t, func(t *stubAppTest) error { return t.App.Unload() })
}

func TestAppUnload_StubWithoutBPF(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_StubWithBPF(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)
	t.World.ExecCommand("bpftool", "prog", "loadall", "fake.bpf.o", "/sys/fs/bpf/same-cgroup-mark", "pinmaps", "/sys/fs/bpf/same-cgroup-mark/maps").CombinedOutput()
	for _, att := range internal.CgroupAttaches() {
		t.World.ExecCommand("bpftool", "cgroup", "attach", "/sys/fs/cgroup",
			att.AttachType, "pinned", "/sys/fs/bpf/same-cgroup-mark/"+att.Name).Run()
	}

	t.Nil(t.App.Unload())
	t.AssertClean()
}

func TestAppUnload_StubBPFDirExists(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)
	t.World.FS[BPFDir] = &fstest.MapFile{Mode: os.ModeDir | internal.BPFMode}

	t.World.Stub.OsRemoveAll.Fail(errStubRemove)

	err := t.App.Unload()
	t.Match(err, "BPF pin directory still exists")
}

func TestAppUnload_StubBPFDirStatError(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)

	t.World.Stub.OsStat.Fail(errStubStat)

	err := t.App.Unload()
	t.Err(err, errStubStat)
}

func TestAppUnload_StubCgroupShow(t *testing.T) {
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
		{name: "Error", retErr: errStubBpftool, wantErr: "cannot verify cgroup attachments"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			t := newStubAppTest(tt)
			t.World.Stub.ExecBpftoolCgroupShow.Returns(tc.ret, tc.retErr)
			err := t.App.Unload()
			if tc.wantErr != "" {
				t.Match(err, tc.wantErr)
			} else {
				t.Nil(err)
			}
		})
	}
}

func TestAppSetMark_StubDoErrors(t *testing.T) {
	testDoErrors(t, func(t *stubAppTest) error { return t.App.SetMark(internal.Mark(0x10000000)) })
}

func TestAppSetMark_StubSuccess(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)
	mark := internal.Mark(0x10000000)

	t.Nil(t.App.SetMark(mark))
	t.DeepEqual(t.World.markBytes, mark.ToLE())
}

func TestAppSetMark_StubError(tt *testing.T) {
	tt.Parallel()
	t := newStubAppTest(tt)

	t.World.Stub.ExecBpftoolMapUpdate.Fail(errStubBpftool)

	err := t.App.SetMark(internal.Mark(0x10000000))
	t.Match(err, "bpftool map update")
}
