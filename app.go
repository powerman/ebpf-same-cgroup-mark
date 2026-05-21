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
	BPFMode    = fs.FileMode(0o750)
	BPFRoot    = "/sys/fs/bpf"
	BPFDir     = BPFRoot + "/same-cgroup-mark"
	CgroupRoot = "/sys/fs/cgroup"

	bpfTimeout = 10 * time.Second
)

// Errors.
var (
	ErrMustBeRoot = errors.New("must be run as root")
)

// App is the main application.
type App interface {
	Load() error
	SetMark(m Mark) error
	Unload() error
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
	err := a.rootCheck()
	if err != nil {
		return err
	}

	_ = a.unloadBPF()

	bpfObjPath, err := a.writeTempBPFObj()
	if err != nil {
		return err
	}
	//nolint:errcheck // cleanup on best-effort basis
	defer os.Remove(bpfObjPath)

	err = a.ensureBPFFS()
	if err != nil {
		return err
	}

	err = a.OsRemoveAll(BPFDir)
	if err != nil {
		return fmt.Errorf("cleanup old pin dir: %w", err)
	}

	err = a.runCmd("bpftool", "prog", "loadall",
		bpfObjPath, BPFDir,
		"pinmaps", BPFDir+"/maps",
	)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, att := range CgroupAttach() {
		progPin := filepath.Join(BPFDir, att.ProgName)
		err = a.runCmd("bpftool", "cgroup", "attach",
			CgroupRoot, att.AttachType, "pinned", progPin,
		)
		if err != nil {
			return fmt.Errorf("attach %s: %w", att.ProgName, err)
		}
	}

	return nil
}

// SetMark updates the mark mask in the eBPF map.
func (a *app) SetMark(m Mark) error {
	leBytes := m.ToLE()

	err := a.runCmd("bpftool", "map", "update",
		"pinned", BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", leBytes[0], leBytes[1], leBytes[2], leBytes[3],
	)
	if err != nil {
		return fmt.Errorf("set mark: %w", err)
	}
	fmt.Printf("Mark mask set to 0x%08x\n", m)
	return nil
}

// Unload detaches and unloads the eBPF program.
func (a *app) Unload() error {
	err := a.rootCheck()
	if err != nil {
		return err
	}

	return a.unloadBPF()
}

// rootCheck verifies that the program is running with root privileges.
func (a *app) rootCheck() error {
	if a.OsGeteuid() != 0 {
		return ErrMustBeRoot
	}

	return nil
}

// unloadBPF detaches the eBPF program from cgroups and removes pinned objects.
func (a *app) unloadBPF() error {
	_, err := a.OsStat(BPFDir)
	if os.IsNotExist(err) {
		return nil
	}

	for _, att := range CgroupAttach() {
		progPin := filepath.Join(BPFDir, att.ProgName)
		_ = a.runCmd("bpftool", "cgroup", "detach",
			CgroupRoot, att.AttachType, "pinned", progPin,
		)
	}

	return a.OsRemoveAll(BPFDir)
}

// ensureBPFFS checks if the BPF filesystem is mounted and mounts it if not.
func (a *app) ensureBPFFS() error {
	err := a.OsMkdirAll(BPFRoot, BPFMode)
	if err != nil {
		return err
	}
	err = a.runCmd("mountpoint", "-q", BPFRoot)
	if err == nil {
		return nil
	}
	out, err := a.CmdOutput("mount", "-t", "bpf", "bpf", BPFRoot)
	if err != nil {
		return fmt.Errorf("mount bpf: %w\n%s", err, out)
	}
	return nil
}

// writeTempBPFObj writes the embedded eBPF object to a temporary file and returns its path.
func (a *app) writeTempBPFObj() (string, error) {
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

// runCmd executes a command with the given arguments and a timeout.
func (a *app) runCmd(args ...string) error {
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
