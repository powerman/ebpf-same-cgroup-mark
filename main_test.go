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

// mockTempFile implements tempFile for testing realWriteTempBPFObj error branches.
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

// saveMocks saves all mockable package vars and registers cleanup via t.Cleanup.
func saveMocks(t *testing.T) {
	t.Helper()
	oldCmdRun := cmdRun
	oldCmdOutput := cmdOutput
	oldGeteuid := osGeteuid
	oldStat := osStat
	oldRemoveAll := osRemoveAll
	oldMkdirAll := osMkdirAll
	oldOsCreateTemp := osCreateTemp
	t.Cleanup(func() {
		cmdRun = oldCmdRun
		cmdOutput = oldCmdOutput
		osGeteuid = oldGeteuid
		osStat = oldStat
		osRemoveAll = oldRemoveAll
		osMkdirAll = oldMkdirAll
		osCreateTemp = oldOsCreateTemp
	})
}

func TestParseMark(tt *testing.T) {
	t := check.T(tt).MustAll()
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
	_, err := parseMark("not-a-number")
	t.NotNil(err)
}

func TestParseMarkOverflow(tt *testing.T) {
	t := check.T(tt).MustAll()
	_, err := parseMark("0x1FFFFFFFF")
	t.NotNil(err)
}

func TestParseMarkMaxUint32(tt *testing.T) {
	t := check.T(tt).MustAll()
	v, err := parseMark("0xFFFFFFFF")
	t.Nil(err)
	t.Equal(v, uint32(0xFFFFFFFF))
}

func TestWriteTempBPFObj(tt *testing.T) {
	t := check.T(tt).MustAll()
	path, err := writeTempBPFObj()
	t.Nil(err)
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	t.Nil(err)

	t.Equal(len(data), len(bpfObj))
	t.DeepEqual(data, bpfObj)
}

func TestWriteTempBPFObjCreateTempError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osCreateTemp = func(_, _ string) (tempFile, error) {
		return nil, errMockMkdir
	}

	_, err := writeTempBPFObj()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "create temp file"))
}

func TestWriteTempBPFObjWriteError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osCreateTemp = func(_, _ string) (tempFile, error) {
		return &mockTempFile{name: "/tmp/test.bpf.o", writeErr: errMockMkdir}, nil
	}

	_, err := writeTempBPFObj()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "write temp file"))
}

func TestWriteTempBPFObjCloseError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osCreateTemp = func(_, _ string) (tempFile, error) {
		return &mockTempFile{name: "/tmp/test.bpf.o", closeErr: errMockMkdir}, nil
	}

	_, err := writeTempBPFObj()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "close temp file"))
}

func TestMarkToLE(tt *testing.T) {
	t := check.T(tt).MustAll()
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
	entries := cgroupAttach()
	t.Equal(len(entries), 4)
	t.Equal(entries[0], cgroupAttachEntry{"same_cgroup_bind4", "cgroup_inet4_bind"})
	t.Equal(entries[1], cgroupAttachEntry{"same_cgroup_bind6", "cgroup_inet6_bind"})
	t.Equal(entries[2], cgroupAttachEntry{"same_cgroup_connect4", "cgroup_inet4_connect"})
	t.Equal(entries[3], cgroupAttachEntry{"same_cgroup_connect6", "cgroup_inet6_connect"})
}

func TestRootCheckAsRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }

	t.Nil(rootCheck())
}

func TestRootCheckAsNonRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 1000 }

	t.Equal(rootCheck(), errMustBeRoot)
}

func TestRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	var gotName string
	var gotArgs []string
	cmdRun = func(_ context.Context, name string, args ...string) error {
		gotName = name
		gotArgs = args
		return nil
	}

	err := run("echo", "hello", "world")
	t.Nil(err)
	t.Equal(gotName, "echo")
	t.DeepEqual(gotArgs, []string{"hello", "world"})
}

func TestRunError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		return errMockCmd
	}

	err := run("false")
	t.NotNil(err)
}

func TestEnsureBPFFSMkdirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osMkdirAll = func(_ string, _ os.FileMode) error {
		return errMockMkdir
	}

	err := ensureBPFFS()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), errMockMkdir.Error()))
}

func TestEnsureBPFFSAlreadyMounted(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	cmdRun = func(_ context.Context, name string, _ ...string) error {
		t.Equal(name, "mountpoint")
		return nil
	}

	t.Nil(ensureBPFFS())
}

func TestEnsureBPFFSMountSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	cmdRun = func(_ context.Context, name string, _ ...string) error {
		t.Equal(name, "mountpoint")
		return errMockNotMounted
	}
	cmdOutput = func(_ context.Context, name string, _ ...string) ([]byte, error) {
		t.Equal(name, "mount")
		return nil, nil
	}

	t.Nil(ensureBPFFS())
}

func TestEnsureBPFFSMountError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		return errMockNotMounted
	}
	cmdOutput = func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		return []byte("mount failure details"), errMockMountFailed
	}

	err := ensureBPFFS()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "mount bpffs"))
}

func TestSetMarkSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	cmdRun = func(_ context.Context, name string, args ...string) error {
		t.Equal(name, "bpftool")
		t.Equal(args[0], "map")
		t.Equal(args[1], "update")
		return nil
	}

	t.Nil(setMark(0x40000000))
}

func TestSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		return errMockBpftool
	}

	err := setMark(0x40000000)
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "set mark"))
}

func TestUnloadNotExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osStat = func(_ string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	t.Nil(unload())
}

func TestUnloadExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osStat = func(_ string) (os.FileInfo, error) {
		return dummyFileInfo{}, nil
	}

	var detachCalls []string
	cmdRun = func(_ context.Context, name string, args ...string) error {
		if name == "bpftool" && len(args) >= 2 && args[0] == "cgroup" && args[1] == "detach" {
			detachCalls = append(detachCalls, strings.Join(args, " "))
		}
		return nil
	}

	var removedPath string
	osRemoveAll = func(path string) error {
		removedPath = path
		return nil
	}

	t.Nil(unload())
	t.Equal(len(detachCalls), 4)
	t.Equal(removedPath, pinDir)
}

func TestLoadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 1000 }

	cmd := &loadCmd{}
	err := cmd.Run()
	t.Equal(err, errMustBeRoot)
}

func TestLoadRunEnsureBPFFSError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error {
		return errMockMkdir
	}

	cmd := &loadCmd{}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), errMockMkdir.Error()))
}

func TestLoadRunWriteTempBPFObjError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osCreateTemp = func(_, _ string) (tempFile, error) {
		return nil, errMockMkdir
	}

	cmd := &loadCmd{}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), errMockMkdir.Error()))
}

func TestLoadRunBPFToolLoadallError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }

	var callCount int
	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		callCount++
		if callCount == 2 {
			return errMockLoadall
		}
		return nil
	}

	cmd := &loadCmd{}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "bpftool loadall"))
}

func TestLoadRunAttachError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }

	var callCount int
	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		callCount++
		if callCount >= 3 {
			return errMockAttach
		}
		return nil
	}

	cmd := &loadCmd{}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "attach"))
}

func TestLoadRunCleanupPinDirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(path string) error {
		if path == pinDir {
			return errMockRemove
		}
		return nil
	}
	cmdRun = func(_ context.Context, _ string, _ ...string) error { return nil }

	cmd := &loadCmd{}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "cleanup old pin dir"))
}

func TestLoadRunParseMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }
	cmdRun = func(_ context.Context, _ string, _ ...string) error { return nil }

	cmd := &loadCmd{Mark: "not-a-valid-mark"}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "invalid mark value"))
}

func TestLoadRunSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }

	var callCount int
	cmdRun = func(_ context.Context, _ string, _ ...string) error {
		callCount++
		if callCount >= 7 {
			return errMockSetMark
		}
		return nil
	}

	cmd := &loadCmd{Mark: "0x40000000"}
	err := cmd.Run()
	t.NotNil(err)
	t.True(strings.Contains(err.Error(), "set mark"))
}

func TestLoadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }
	cmdRun = func(_ context.Context, _ string, _ ...string) error { return nil }

	cmd := &loadCmd{Mark: ""}
	t.Nil(cmd.Run())
}

func TestLoadRunSuccessWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	osMkdirAll = func(_ string, _ os.FileMode) error { return nil }
	osRemoveAll = func(_ string) error { return nil }
	cmdRun = func(_ context.Context, _ string, _ ...string) error { return nil }

	cmd := &loadCmd{Mark: "0x40000000"}
	t.Nil(cmd.Run())
}

func TestUnloadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 1000 }

	cmd := &unloadCmd{}
	err := cmd.Run()
	t.Equal(err, errMustBeRoot)
}

func TestUnloadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	saveMocks(tt)

	osGeteuid = func() int { return 0 }
	osStat = func(_ string) (os.FileInfo, error) { return nil, os.ErrNotExist }

	cmd := &unloadCmd{}
	t.Nil(cmd.Run())
}
