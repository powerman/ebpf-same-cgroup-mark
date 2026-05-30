//go:generate mise run mockgen --no-test-pkg
//go:generate mise run go-mockgen --no-test-pkg -i World -i WorldOsFile
package app

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"strconv"
)

// Constants.
const (
	BPFMode    = fs.FileMode(0o750)
	BPFRoot    = "/sys/fs/bpf"
	BPFDir     = BPFRoot + "/same-cgroup-mark"
	CgroupRoot = "/sys/fs/cgroup"
)

// Errors.
var (
	ErrMustBeRoot       = errors.New("must be run as root")
	ErrInvalidMarkValue = errors.New("invalid mark value")
	ErrMarkOverflow     = errors.New("mark value exceeds 32-bit maximum (0xFFFFFFFF)")
)

// App is the main application.
//
//nolint:iface // Used as a port by external packages.
type App interface {
	Load() error
	SetMark(m Mark) error
	Unload() error
}

// World abstracts OS and exec dependencies for testability.
type World interface {
	Mountpoint(dir string) error
	MountBPF(fstype, target string) ([]byte, error)
	BpftoolProgLoadAll(bpfObjPath, bpffs, mapsDir string) ([]byte, error)
	BpftoolCgroupAttach(cgroup, attachType, progPin string) error
	BpftoolCgroupDetach(cgroup, attachType, progPin string) error
	BpftoolMapUpdate(args ...string) error
	BpftoolCgroupShow(cgroup string) ([]byte, error)
	OsCreateTemp(dir, pattern string) (WorldOsFile, error)
	OsGeteuid() int
	OsMkdirAll(path string, perm os.FileMode) error
	OsRemove(name string) error
	OsRemoveAll(path string) error
	OsStat(name string) (os.FileInfo, error)
}

// WorldOsFile allows mocking [os.File] operations in tests.
type WorldOsFile interface {
	Close() error
	Name() string
	Write(p []byte) (n int, err error)
}

// Mark is a validated 32-bit mark value.
// It implements [encoding.TextUnmarshaler] for use as a Kong custom type.
type Mark uint32

// UnmarshalText implements [encoding.TextUnmarshaler] for Kong flag parsing.
func (m *Mark) UnmarshalText(text []byte) error {
	return m.parse(string(text))
}

// parse parses a hexadecimal string into a Mark value.
func (m *Mark) parse(s string) error {
	hex := s
	if len(hex) > 2 && (hex[:2] == "0x" || hex[:2] == "0X") {
		hex = hex[2:]
	}
	v, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrInvalidMarkValue, s)
	}
	if v > math.MaxUint32 {
		return fmt.Errorf("%w: %q", ErrMarkOverflow, s)
	}
	*m = Mark(v)
	return nil
}

// ToLE converts a Mark value to a little-endian hexadecimal string array for bpftool.
func (m *Mark) ToLE() [4]string {
	hex := fmt.Sprintf("%08x", *m)
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}
