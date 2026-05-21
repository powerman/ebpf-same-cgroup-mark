package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/powerman/check"
)

// Package-level sentinel errors for mocks (err113 requires static errors).
var (
	errMockCmd         = errors.New("mock cmd error")
	errMockMkdir       = errors.New("mock mkdir error")
	errMockNotMounted  = errors.New("mock not mounted error")
	errMockMountFailed = errors.New("mock mount failed error")
	errMockLoadall     = errors.New("mock loadall error")
	errMockAttach      = errors.New("mock attach error")
	errMockRemove      = errors.New("mock remove error")
	errMockSetMark     = errors.New("mock set mark error")
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

// mockTempFile implements TempFile for testing writeTempBPFObj error branches.
type mockTempFile struct {
	name      string
	writeErr  error
	closeErr  error
	wroteData []byte
}

func (m *mockTempFile) Write(p []byte) (int, error) {
	m.wroteData = p
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(p), nil
}

func (m *mockTempFile) Close() error { return m.closeErr }
func (m *mockTempFile) Name() string { return m.name }

// mockWorld implements World for tests, falling back to RealWorld for unset methods.
type mockWorld struct {
	cmdRunFunc       func(ctx context.Context, name string, args ...string) error
	cmdOutputFunc    func(name string, args ...string) ([]byte, error)
	osCreateTempFunc func(dir, pattern string) (TempFile, error)
	osGeteuidFunc    func() int
	osMkdirAllFunc   func(path string, perm os.FileMode) error
	osRemoveAllFunc  func(path string) error
	osStatFunc       func(name string) (os.FileInfo, error)
}

func (m *mockWorld) CmdRun(ctx context.Context, name string, args ...string) error {
	if m.cmdRunFunc != nil {
		return m.cmdRunFunc(ctx, name, args...)
	}
	return RealWorld{}.CmdRun(ctx, name, args...)
}

func (m *mockWorld) CmdOutput(name string, args ...string) ([]byte, error) {
	if m.cmdOutputFunc != nil {
		return m.cmdOutputFunc(name, args...)
	}
	return RealWorld{}.CmdOutput(name, args...)
}

func (m *mockWorld) OsCreateTemp(dir, pattern string) (TempFile, error) {
	if m.osCreateTempFunc != nil {
		return m.osCreateTempFunc(dir, pattern)
	}
	return RealWorld{}.OsCreateTemp(dir, pattern)
}

func (m *mockWorld) OsGeteuid() int {
	if m.osGeteuidFunc != nil {
		return m.osGeteuidFunc()
	}
	return RealWorld{}.OsGeteuid()
}

func (m *mockWorld) OsMkdirAll(path string, perm os.FileMode) error {
	if m.osMkdirAllFunc != nil {
		return m.osMkdirAllFunc(path, perm)
	}
	return RealWorld{}.OsMkdirAll(path, perm)
}

func (m *mockWorld) OsRemoveAll(path string) error {
	if m.osRemoveAllFunc != nil {
		return m.osRemoveAllFunc(path)
	}
	return RealWorld{}.OsRemoveAll(path)
}

func (m *mockWorld) OsStat(name string) (os.FileInfo, error) {
	if m.osStatFunc != nil {
		return m.osStatFunc(name)
	}
	return RealWorld{}.OsStat(name)
}

func TestParseMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	tests := []struct {
		input string
		want  uint32
	}{
		{"0x40000000", 0x40000000},
		{"0x20000000", 0x20000000},
		{"0x1", 1},
		{"40000000", 0x40000000},
	}
	for _, tc := range tests {
		got, err := parseMark(tc.input)
		t.Nil(err)
		t.Equal(got, tc.want)
	}
}

func TestParseMarkInvalid(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	_, err := parseMark("not-a-number")
	t.NotNil(err)
}

func TestParseMarkOverflow(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	_, err := parseMark("0x1FFFFFFFF")
	t.NotNil(err)
}

func TestParseMarkMaxUint32(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	v, err := parseMark("0xFFFFFFFF")
	t.Nil(err)
	t.Equal(v, uint32(0xFFFFFFFF))
}

func TestWriteTempBPFObj(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{World: &RealWorld{}}
	path, err := cmd.writeTempBPFObj()
	t.Nil(err)
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	t.Nil(err)

	t.DeepEqual(data, bpfObj)
}

func TestWriteTempBPFObjCreateTempError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osCreateTempFunc: func(_, _ string) (TempFile, error) {
				return nil, errMockMkdir
			},
		},
	}

	_, err := cmd.writeTempBPFObj()
	t.Match(err, "create temp file")
}

func TestWriteTempBPFObjWriteError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osCreateTempFunc: func(_, _ string) (TempFile, error) {
				return &mockTempFile{name: "/tmp/test.bpf.o", writeErr: errMockMkdir}, nil
			},
		},
	}

	_, err := cmd.writeTempBPFObj()
	t.Match(err, "write temp file")
}

func TestWriteTempBPFObjCloseError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osCreateTempFunc: func(_, _ string) (TempFile, error) {
				return &mockTempFile{name: "/tmp/test.bpf.o", closeErr: errMockMkdir}, nil
			},
		},
	}

	_, err := cmd.writeTempBPFObj()
	t.Match(err, "close temp file")
}

func TestMarkToLE(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	tests := []struct {
		mark uint32
		want [4]string
	}{
		{0x40000000, [4]string{"00", "00", "00", "40"}},
		{0x00000001, [4]string{"01", "00", "00", "00"}},
		{0x10000000, [4]string{"00", "00", "00", "10"}},
		{0xFFFFFFFF, [4]string{"ff", "ff", "ff", "ff"}},
		{0xABCDEF01, [4]string{"01", "ef", "cd", "ab"}},
	}
	for _, tc := range tests {
		t.DeepEqual(markToLE(tc.mark), tc.want)
	}
}

func TestCgroupAttach(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	entries := cgroupAttach()
	t.Len(entries, 4)
	t.Equal(entries[0], cgroupAttachEntry{"same_cgroup_bind4", "cgroup_inet4_bind"})
	t.Equal(entries[1], cgroupAttachEntry{"same_cgroup_bind6", "cgroup_inet6_bind"})
	t.Equal(entries[2], cgroupAttachEntry{"same_cgroup_connect4", "cgroup_inet4_connect"})
	t.Equal(entries[3], cgroupAttachEntry{"same_cgroup_connect6", "cgroup_inet6_connect"})
}

func TestRootCheckAsRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	w := &mockWorld{osGeteuidFunc: func() int { return 0 }}
	t.Nil(rootCheck(w))
}

func TestRootCheckAsNonRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	w := &mockWorld{osGeteuidFunc: func() int { return 1000 }}
	t.Equal(rootCheck(w), errMustBeRoot)
}

func TestRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var gotName string
	var gotArgs []string
	w := &mockWorld{
		cmdRunFunc: func(_ context.Context, name string, args ...string) error {
			gotName = name
			gotArgs = args
			return nil
		},
	}

	err := run(w, "echo", "hello", "world")
	t.Nil(err)
	t.Equal(gotName, "echo")
	t.DeepEqual(gotArgs, []string{"hello", "world"})
}

func TestRunError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	w := &mockWorld{
		cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
			return errMockCmd
		},
	}

	err := run(w, "false")
	t.NotNil(err)
}

func TestEnsureBPFFSMkdirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osMkdirAllFunc: func(_ string, _ os.FileMode) error {
				return errMockMkdir
			},
		},
	}

	err := cmd.ensureBPFFS()
	t.Match(err, errMockMkdir.Error())
}

func TestEnsureBPFFSAlreadyMounted(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osMkdirAllFunc: func(_ string, _ os.FileMode) error { return nil },
			cmdRunFunc: func(_ context.Context, name string, _ ...string) error {
				t.Equal(name, "mountpoint")
				return nil
			},
		},
	}

	t.Nil(cmd.ensureBPFFS())
}

func TestEnsureBPFFSMountSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osMkdirAllFunc: func(_ string, _ os.FileMode) error { return nil },
			cmdRunFunc: func(_ context.Context, name string, _ ...string) error {
				t.Equal(name, "mountpoint")
				return errMockNotMounted
			},
			cmdOutputFunc: func(name string, _ ...string) ([]byte, error) {
				t.Equal(name, "mount")
				return nil, nil
			},
		},
	}

	t.Nil(cmd.ensureBPFFS())
}

func TestEnsureBPFFSMountError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			osMkdirAllFunc: func(_ string, _ os.FileMode) error { return nil },
			cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
				return errMockNotMounted
			},
			cmdOutputFunc: func(_ string, _ ...string) ([]byte, error) {
				return []byte("mount failure details"), errMockMountFailed
			},
		},
	}

	err := cmd.ensureBPFFS()
	t.Match(err, "mount bpf")
}

func TestSetMarkSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			cmdRunFunc: func(_ context.Context, name string, args ...string) error {
				t.Equal(name, "bpftool")
				t.Equal(args[0], "map")
				t.Equal(args[1], "update")
				return nil
			},
		},
	}

	t.Nil(cmd.setMark(0x40000000))
}

func TestSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{
		World: &mockWorld{
			cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
				return errMockBpftool
			},
		},
	}

	err := cmd.setMark(0x40000000)
	t.Match(err, "set mark")
}

func TestUnloadNotExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	w := &mockWorld{
		osStatFunc: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	t.Nil(unload(w))
}

func TestUnloadExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var detachCalls []string
	var removedPath string
	w := &mockWorld{
		osStatFunc: func(_ string) (os.FileInfo, error) {
			return dummyFileInfo{}, nil
		},
		cmdRunFunc: func(_ context.Context, name string, args ...string) error {
			if name == "bpftool" && len(args) >= 2 && args[0] == "cgroup" && args[1] == "detach" {
				detachCalls = append(detachCalls, strings.Join(args, " "))
			}
			return nil
		},
		osRemoveAllFunc: func(path string) error {
			removedPath = path
			return nil
		},
	}

	t.Nil(unload(w))
	t.Len(detachCalls, 4)
	t.Equal(removedPath, pinDir)
}

func TestLoadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc: func() int { return 1000 },
	})
	t.Equal(err, errMustBeRoot)
}

func TestLoadRunEnsureBPFFSError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:  func() int { return 0 },
		osStatFunc:     func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc: func(_ string, _ os.FileMode) error { return errMockMkdir },
	})
	t.Match(err, errMockMkdir.Error())
}

func TestLoadRunWriteTempBPFObjError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc: func() int { return 0 },
		osStatFunc:    func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osCreateTempFunc: func(_, _ string) (TempFile, error) {
			return nil, errMockMkdir
		},
	})
	t.Match(err, errMockMkdir.Error())
}

func TestLoadRunBPFToolLoadallError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var callCount int
	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
			callCount++
			if callCount == 2 {
				return errMockLoadall
			}
			return nil
		},
	})
	t.Match(err, "bpftool loadall")
}

func TestLoadRunAttachError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var callCount int
	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
			callCount++
			if callCount >= 3 {
				return errMockAttach
			}
			return nil
		},
	})
	t.Match(err, "attach")
}

func TestLoadRunCleanupPinDirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:  func() int { return 0 },
		osStatFunc:     func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc: func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(path string) error {
			if path == pinDir {
				return errMockRemove
			}
			return nil
		},
		cmdRunFunc: func(_ context.Context, _ string, _ ...string) error { return nil },
	})
	t.Match(err, "cleanup old pin dir")
}

func TestLoadRunParseMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{Mark: "not-a-valid-mark"}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc:      func(_ context.Context, _ string, _ ...string) error { return nil },
	})
	t.Match(err, "invalid mark value")
}

func TestLoadRunSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	var callCount int
	cmd := &loadCmd{Mark: "0x40000000"}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc: func(_ context.Context, _ string, _ ...string) error {
			callCount++
			if callCount >= 7 {
				return errMockSetMark
			}
			return nil
		},
	})
	t.Match(err, "set mark")
}

func TestLoadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{Mark: ""}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc:      func(_ context.Context, _ string, _ ...string) error { return nil },
	})
	t.Nil(err)
}

func TestLoadRunSuccessWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &loadCmd{Mark: "0x40000000"}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc:   func() int { return 0 },
		osStatFunc:      func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		osMkdirAllFunc:  func(_ string, _ os.FileMode) error { return nil },
		osRemoveAllFunc: func(_ string) error { return nil },
		cmdRunFunc:      func(_ context.Context, _ string, _ ...string) error { return nil },
	})
	t.Nil(err)
}

func TestUnloadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &unloadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc: func() int { return 1000 },
	})
	t.Equal(err, errMustBeRoot)
}

func TestUnloadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &unloadCmd{}
	err := cmd.Run(&mockWorld{
		osGeteuidFunc: func() int { return 0 },
		osStatFunc:    func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist },
	})
	t.Nil(err)
}
