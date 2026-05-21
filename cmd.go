package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BPFObj is the embedded eBPF object file compiled from same-cgroup-mark.bpf.c.
//
//go:embed .cache/same-cgroup-mark.bpf.o
var BPFObj []byte

// Constants.
const (
	PinDir     = "/sys/fs/bpf/same-cgroup-mark"
	cgroupPath = "/sys/fs/cgroup"
	BPFFSMode  = fs.FileMode(0o750)
	bpfTimeout = 10 * time.Second
)

// Errors.
var (
	ErrMustBeRoot   = errors.New("must be run as root")
	ErrMarkOverflow = errors.New("mark value exceeds 32-bit maximum (0xFFFFFFFF)")
)

// LoadCmd loads and attaches the eBPF program.
type LoadCmd struct {
	World

	Mark string `help:"Mark mask (e.g. 0x40000000)." short:"m"`
}

// Run executes the LoadCmd.
func (c *LoadCmd) Run(world World) error {
	c.World = world

	err := RootCheck(c.World)
	if err != nil {
		return err
	}

	_ = UnloadBPF(c.World)

	bpfObjPath, err := c.WriteTempBPFObj()
	if err != nil {
		return err
	}
	//nolint:errcheck // cleanup on best-effort basis
	defer os.Remove(bpfObjPath)

	err = c.EnsureBPFFS()
	if err != nil {
		return err
	}

	err = c.OsRemoveAll(PinDir)
	if err != nil {
		return fmt.Errorf("cleanup old pin dir: %w", err)
	}

	err = RunCmd(c.World, "bpftool", "prog", "loadall",
		bpfObjPath, PinDir,
		"pinmaps", PinDir+"/maps",
	)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, a := range CgroupAttach() {
		progPin := filepath.Join(PinDir, a.ProgName)
		err = RunCmd(c.World, "bpftool", "cgroup", "attach",
			cgroupPath, a.AttachType, "pinned", progPin,
		)
		if err != nil {
			return fmt.Errorf("attach %s: %w", a.ProgName, err)
		}
	}

	if c.Mark != "" {
		mark, err := ParseMark(c.Mark)
		if err != nil {
			return err
		}
		err = c.SetMark(mark)
		if err != nil {
			return err
		}
	}

	return nil
}

// SetMark updates the mark mask in the eBPF map.
func (c *LoadCmd) SetMark(mark uint32) error {
	leBytes := MarkToLE(mark)

	err := RunCmd(c.World, "bpftool", "map", "update",
		"pinned", PinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", leBytes[0], leBytes[1], leBytes[2], leBytes[3],
	)
	if err != nil {
		return fmt.Errorf("set mark: %w", err)
	}
	fmt.Printf("Mark mask set to 0x%08x\n", mark)
	return nil
}

// EnsureBPFFS checks if the BPF filesystem is mounted and mounts it if not.
func (c *LoadCmd) EnsureBPFFS() error {
	err := c.OsMkdirAll("/sys/fs/bpf", BPFFSMode)
	if err != nil {
		return err
	}
	err = RunCmd(c.World, "mountpoint", "-q", "/sys/fs/bpf")
	if err == nil {
		return nil
	}
	out, err := c.CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")
	if err != nil {
		return fmt.Errorf("mount bpf: %w\n%s", err, out)
	}
	return nil
}

// WriteTempBPFObj writes the embedded eBPF object to a temporary file and returns its path.
func (c *LoadCmd) WriteTempBPFObj() (string, error) {
	f, err := c.OsCreateTemp("", "same-cgroup-mark.*.bpf.o")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	_, err = f.Write(BPFObj)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	err = f.Close()
	if err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return f.Name(), nil
}

// UnloadCmd detaches and unloads the eBPF program.
type UnloadCmd struct {
	World
}

// Run executes the UnloadCmd.
func (c *UnloadCmd) Run(world World) error {
	c.World = world

	err := RootCheck(c.World)
	if err != nil {
		return err
	}

	return UnloadBPF(c.World)
}

// RootCheck verifies that the program is running with root privileges.
func RootCheck(w World) error {
	if w.OsGeteuid() != 0 {
		return ErrMustBeRoot
	}

	return nil
}

// UnloadBPF detaches the eBPF program from cgroups and removes pinned objects.
func UnloadBPF(w World) error {
	_, err := w.OsStat(PinDir)
	if os.IsNotExist(err) {
		return nil
	}

	for _, a := range CgroupAttach() {
		progPin := filepath.Join(PinDir, a.ProgName)
		_ = RunCmd(w, "bpftool", "cgroup", "detach",
			cgroupPath, a.AttachType, "pinned", progPin,
		)
	}

	return w.OsRemoveAll(PinDir)
}

// CgroupAttachEntry represents a single eBPF program and its corresponding cgroup attach type.
type CgroupAttachEntry struct {
	ProgName, AttachType string
}

// CgroupAttach returns the list of eBPF programs and their corresponding cgroup attach types.
func CgroupAttach() []CgroupAttachEntry {
	return []CgroupAttachEntry{
		{"same_cgroup_bind4", "cgroup_inet4_bind"},
		{"same_cgroup_bind6", "cgroup_inet6_bind"},
		{"same_cgroup_connect4", "cgroup_inet4_connect"},
		{"same_cgroup_connect6", "cgroup_inet6_connect"},
	}
}

// MarkToLE converts a uint32 mark value to a little-endian hexadecimal string array for bpftool.
func MarkToLE(mark uint32) [4]string {
	hex := fmt.Sprintf("%08x", mark)
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}

// ParseMark parses a hexadecimal string into a uint32 mark value.
func ParseMark(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	if err != nil {
		return 0, fmt.Errorf("invalid mark value %q: %w", s, err)
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("%w: 0x%X", ErrMarkOverflow, v)
	}
	return uint32(v), nil
}

// RunCmd executes a command with the given arguments and a timeout.
func RunCmd(w World, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bpfTimeout)
	defer cancel()

	return w.CmdRun(ctx, args[0], args[1:]...)
}
