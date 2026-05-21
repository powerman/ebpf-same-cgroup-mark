package main_test

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/powerman/check"
	"go.uber.org/mock/gomock"

	main "github.com/powerman/ebpf-same-cgroup-mark"
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
		got, err := main.ParseMark(tc.input)
		t.Nil(err)
		t.Equal(got, tc.want)
	}
}

func TestParseMarkInvalid(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	_, err := main.ParseMark("not-a-number")
	t.NotNil(err)
}

func TestParseMarkOverflow(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	_, err := main.ParseMark("0x1FFFFFFFF")
	t.NotNil(err)
}

func TestParseMarkMaxUint32(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	v, err := main.ParseMark("0xFFFFFFFF")
	t.Nil(err)
	t.Equal(v, uint32(0xFFFFFFFF))
}

func TestWriteTempBPFObj(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	cmd := &main.LoadCmd{World: &main.RealWorld{}}
	path, err := cmd.WriteTempBPFObj()
	t.Nil(err)
	defer os.Remove(path)

	data, err := os.ReadFile(path)
	t.Nil(err)

	t.DeepEqual(data, main.BPFObj)
}

func TestWriteTempBPFObjCreateTempError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(nil, errMockMkdir)

	cmd := &main.LoadCmd{World: w}
	_, err := cmd.WriteTempBPFObj()
	t.Match(err, "create temp file")
}

func TestWriteTempBPFObjWriteError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(0, errMockMkdir)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	cmd := &main.LoadCmd{World: w}
	_, err := cmd.WriteTempBPFObj()
	t.Match(err, "write temp file")
}

func TestWriteTempBPFObjCloseError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsCreateTemp(gomock.Any(), gomock.Any()).Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(errMockMkdir)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")

	cmd := &main.LoadCmd{World: w}
	_, err := cmd.WriteTempBPFObj()
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
		t.DeepEqual(main.MarkToLE(tc.mark), tc.want)
	}
}

func TestCgroupAttach(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	entries := main.CgroupAttach()
	t.Len(entries, 4)
	t.Equal(entries[0], main.CgroupAttachEntry{"same_cgroup_bind4", "cgroup_inet4_bind"})
	t.Equal(entries[1], main.CgroupAttachEntry{"same_cgroup_bind6", "cgroup_inet6_bind"})
	t.Equal(entries[2], main.CgroupAttachEntry{"same_cgroup_connect4", "cgroup_inet4_connect"})
	t.Equal(entries[3], main.CgroupAttachEntry{"same_cgroup_connect6", "cgroup_inet6_connect"})
}

func TestRootCheckAsRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)

	t.Nil(main.RootCheck(w))
}

func TestRootCheckAsNonRoot(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(1000)

	t.Equal(main.RootCheck(w), main.ErrMustBeRoot)
}

func TestRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "echo", "hello", "world").Return(nil)

	err := main.RunCmd(w, "echo", "hello", "world")
	t.Nil(err)
}

func TestRunError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "false").Return(errMockCmd)

	err := main.RunCmd(w, "false")
	t.NotNil(err)
}

func TestEnsureBPFFSMkdirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	cmd := &main.LoadCmd{World: w}
	err := cmd.EnsureBPFFS()
	t.Match(err, errMockMkdir.Error())
}

func TestEnsureBPFFSAlreadyMounted(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)

	cmd := &main.LoadCmd{World: w}
	t.Nil(cmd.EnsureBPFFS())
}

func TestEnsureBPFFSMountSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return(nil, nil)

	cmd := &main.LoadCmd{World: w}
	t.Nil(cmd.EnsureBPFFS())
}

func TestEnsureBPFFSMountError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(errMockNotMounted)
	w.EXPECT().CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").Return([]byte("mount failure details"), errMockMountFailed)

	cmd := &main.LoadCmd{World: w}
	err := cmd.EnsureBPFFS()
	t.Match(err, "mount bpf")
}

func TestSetMarkSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)

	cmd := &main.LoadCmd{World: w}
	t.Nil(cmd.SetMark(0x40000000))
}

func TestSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockBpftool)

	cmd := &main.LoadCmd{World: w}
	err := cmd.SetMark(0x40000000)
	t.Match(err, "set mark")
}

func TestUnloadNotExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	t.Nil(main.UnloadBPF(w))
}

func TestUnloadExists(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsStat(main.PinDir).Return(dummyFileInfo{}, nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "detach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)

	t.Nil(main.UnloadBPF(w))
}

func TestLoadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(1000)

	cmd := &main.LoadCmd{}
	t.Equal(cmd.Run(w), main.ErrMustBeRoot)
}

func TestLoadRunEnsureBPFFSError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(errMockMkdir)

	cmd := &main.LoadCmd{}
	err := cmd.Run(w)
	t.Match(err, errMockMkdir.Error())
}

func TestLoadRunWriteTempBPFObjError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(nil, errMockMkdir)

	cmd := &main.LoadCmd{}
	err := cmd.Run(w)
	t.Match(err, errMockMkdir.Error())
}

func TestLoadRunBPFToolLoadallError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(errMockLoadall)

	cmd := &main.LoadCmd{}
	err := cmd.Run(w)
	t.Match(err, "bpftool loadall")
}

func TestLoadRunAttachError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(errMockAttach)

	cmd := &main.LoadCmd{}
	err := cmd.Run(w)
	t.Match(err, "attach")
}

func TestLoadRunCleanupPinDirError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(errMockRemove)

	cmd := &main.LoadCmd{}
	err := cmd.Run(w)
	t.Match(err, "cleanup old pin dir")
}

func TestLoadRunParseMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)

	cmd := &main.LoadCmd{Mark: "not-a-valid-mark"}
	err := cmd.Run(w)
	t.Match(err, "invalid mark value")
}

func TestLoadRunSetMarkError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(errMockSetMark)

	cmd := &main.LoadCmd{Mark: "0x40000000"}
	err := cmd.Run(w)
	t.Match(err, "set mark")
}

func TestLoadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)

	cmd := &main.LoadCmd{Mark: ""}
	t.Nil(cmd.Run(w))
}

func TestLoadRunSuccessWithMark(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	tf := main.NewMockTempFile(ctrl)

	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)
	w.EXPECT().OsCreateTemp("", "same-cgroup-mark.*.bpf.o").Return(tf, nil)
	tf.EXPECT().Write(gomock.Any()).Return(len(main.BPFObj), nil)
	tf.EXPECT().Close().Return(nil)
	tf.EXPECT().Name().Return("/tmp/test.bpf.o")
	w.EXPECT().OsMkdirAll("/sys/fs/bpf", main.BPFFSMode).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "mountpoint", "-q", "/sys/fs/bpf").Return(nil)
	w.EXPECT().OsRemoveAll(main.PinDir).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "prog", "loadall",
		gomock.Any(), main.PinDir, "pinmaps", main.PinDir+"/maps",
	).Return(nil)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "cgroup", "attach",
		"/sys/fs/cgroup", gomock.Any(), "pinned", gomock.Any(),
	).Return(nil).Times(4)
	w.EXPECT().CmdRun(gomock.Any(), "bpftool", "map", "update",
		"pinned", main.PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
	).Return(nil)

	cmd := &main.LoadCmd{Mark: "0x40000000"}
	t.Nil(cmd.Run(w))
}

func TestUnloadRunRootCheckError(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(1000)

	cmd := &main.UnloadCmd{}
	t.Equal(cmd.Run(w), main.ErrMustBeRoot)
}

func TestUnloadRunSuccess(tt *testing.T) {
	t := check.T(tt).MustAll()
	t.Parallel()

	ctrl := gomock.NewController(tt)
	w := main.NewMockWorld(ctrl)
	w.EXPECT().OsGeteuid().Return(0)
	w.EXPECT().OsStat(main.PinDir).Return(nil, os.ErrNotExist)

	cmd := &main.UnloadCmd{}
	t.Nil(cmd.Run(w))
}
