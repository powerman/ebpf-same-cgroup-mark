//go:generate mise exec -- sh -c "mockgen -package=\"${DOLLAR}1_test\" -source=\"${DOLLAR}2\" -destination=\"mock.$(basename \"${DOLLAR}2\" .go)_test.go\"" _ $GOPACKAGE $GOFILE

package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	ErrMustBeRoot = errors.New("must be run as root")
)

// App is the main application.
type App interface {
	Load() error
	Unload() error
	RootCheck() error
	UnloadBPF() error
	SetMark(mark uint32) error
	EnsureBPFFS() error
	WriteTempBPFObj() (string, error)
	RunCmd(args ...string) error
}

type app struct {
	World
}

// NewApp creates a new App with the given World.
func NewApp(world World) *app {
	return &app{World: world}
}

// Load loads and attaches the eBPF program.
func (a *app) Load() error {
	err := a.RootCheck()
	if err != nil {
		return err
	}

	_ = a.UnloadBPF()

	bpfObjPath, err := a.WriteTempBPFObj()
	if err != nil {
		return err
	}
	//nolint:errcheck // cleanup on best-effort basis
	defer os.Remove(bpfObjPath)

	err = a.EnsureBPFFS()
	if err != nil {
		return err
	}

	err = a.OsRemoveAll(PinDir)
	if err != nil {
		return fmt.Errorf("cleanup old pin dir: %w", err)
	}

	err = a.RunCmd("bpftool", "prog", "loadall",
		bpfObjPath, PinDir,
		"pinmaps", PinDir+"/maps",
	)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, att := range CgroupAttach() {
		progPin := filepath.Join(PinDir, att.ProgName)
		err = a.RunCmd("bpftool", "cgroup", "attach",
			cgroupPath, att.AttachType, "pinned", progPin,
		)
		if err != nil {
			return fmt.Errorf("attach %s: %w", att.ProgName, err)
		}
	}

	return nil
}

// Unload detaches and unloads the eBPF program.
func (a *app) Unload() error {
	err := a.RootCheck()
	if err != nil {
		return err
	}

	return a.UnloadBPF()
}

// RootCheck verifies that the program is running with root privileges.
func (a *app) RootCheck() error {
	if a.OsGeteuid() != 0 {
		return ErrMustBeRoot
	}

	return nil
}

// UnloadBPF detaches the eBPF program from cgroups and removes pinned objects.
func (a *app) UnloadBPF() error {
	_, err := a.OsStat(PinDir)
	if os.IsNotExist(err) {
		return nil
	}

	for _, att := range CgroupAttach() {
		progPin := filepath.Join(PinDir, att.ProgName)
		_ = a.RunCmd("bpftool", "cgroup", "detach",
			cgroupPath, att.AttachType, "pinned", progPin,
		)
	}

	return a.OsRemoveAll(PinDir)
}

// MarkToLE converts a uint32 mark value to a little-endian hexadecimal string array for bpftool.
func MarkToLE(mark uint32) [4]string {
	hex := fmt.Sprintf("%08x", mark)
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}

// SetMark updates the mark mask in the eBPF map.
func (a *app) SetMark(mark uint32) error {
	leBytes := MarkToLE(mark)

	err := a.RunCmd("bpftool", "map", "update",
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
func (a *app) EnsureBPFFS() error {
	err := a.OsMkdirAll("/sys/fs/bpf", BPFFSMode)
	if err != nil {
		return err
	}
	err = a.RunCmd("mountpoint", "-q", "/sys/fs/bpf")
	if err == nil {
		return nil
	}
	out, err := a.CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")
	if err != nil {
		return fmt.Errorf("mount bpf: %w\n%s", err, out)
	}
	return nil
}

// WriteTempBPFObj writes the embedded eBPF object to a temporary file and returns its path.
func (a *app) WriteTempBPFObj() (string, error) {
	f, err := a.OsCreateTemp("", "same-cgroup-mark.*.bpf.o")
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

// RunCmd executes a command with the given arguments and a timeout.
func (a *app) RunCmd(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bpfTimeout)
	defer cancel()

	return a.CmdRun(ctx, args[0], args[1:]...)
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
