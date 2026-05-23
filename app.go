//go:generate mise exec -- sh -c "mockgen -package=\"${DOLLAR}1_test\" -source=\"${DOLLAR}2\" -destination=\"mock.$(basename \"${DOLLAR}2\" .go)_test.go\"" _ $GOPACKAGE $GOFILE

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
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
)

// Errors.
var (
	ErrMustBeRoot   = errors.New("must be run as root")
	errBPFDirExists = errors.New("BPF pin directory still exists")
	errProgAttached = errors.New("BPF program still attached to cgroup")
)

// CgroupAttachEntry represents a single eBPF program and its corresponding cgroup attach type.
type CgroupAttachEntry struct {
	ProgName   string `json:"name"`
	AttachType string `json:"attach_type"`
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
	return a.do(a.load)
}

func (a *app) load() (err error) {
	err = a.unload()
	if err != nil {
		return fmt.Errorf("cleanup previous state: %w", err)
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, a.unload())
		}
	}()

	bpfObjPath, err := a.writeTempBPFObj()
	if err != nil {
		return err
	}
	defer a.OsRemove(bpfObjPath) //nolint:errcheck // Cleanup on best-effort basis.

	err = a.bpftoolLoadAll(bpfObjPath)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, att := range CgroupAttach() {
		progPin := filepath.Join(BPFDir, att.ProgName)
		err = a.bpftoolAttach(att.AttachType, progPin)
		if err != nil {
			return fmt.Errorf("bpftool attach %s %s: %w", att.AttachType, att.ProgName, err)
		}
	}

	return nil
}

// SetMark updates the mark mask in the eBPF map.
func (a *app) SetMark(m Mark) error {
	return a.do(func() error { return a.setMark(m) })
}

func (a *app) setMark(m Mark) error {
	err := a.bpftoolMapUpdateMark(m)
	if err != nil {
		return fmt.Errorf("bpftool map update: %w", err)
	}
	return nil
}

// Unload detaches and unloads the eBPF program.
func (a *app) Unload() error {
	return a.do(a.unload)
}

func (a *app) unload() error {
	for _, att := range CgroupAttach() {
		progPin := filepath.Join(BPFDir, att.ProgName)
		_ = a.bpftoolDetach(att.AttachType, progPin)
	}
	_ = a.OsRemoveAll(BPFDir)

	return a.checkUnloaded()
}

func (a *app) do(f func() error) error {
	err := a.rootCheck()
	if err == nil {
		err = a.ensureBPFFS()
	}
	if err == nil {
		err = f()
	}
	return err
}

// rootCheck verifies that the program is running with root privileges.
func (a *app) rootCheck() error {
	if a.OsGeteuid() != 0 {
		return ErrMustBeRoot
	}
	return nil
}

// ensureBPFFS checks if the BPF filesystem is mounted and mounts it if not.
func (a *app) ensureBPFFS() error {
	if a.isBPFMounted() {
		return nil
	}

	err := a.OsMkdirAll(BPFRoot, BPFMode)
	if err != nil {
		return err
	}
	out, err := a.mountBPF()
	if err != nil {
		return fmt.Errorf("mount bpf: %w\n%s", err, out)
	}

	fmt.Println(BPFRoot + " mounted")
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
		_ = a.OsRemove(f.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	err = f.Close()
	if err != nil {
		_ = a.OsRemove(f.Name())
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return f.Name(), nil
}

// checkUnloaded verifies the eBPF program is fully unloaded, including all cgroup attachments.
func (a *app) checkUnloaded() error {
	var errs error

	_, statErr := a.OsStat(BPFDir)
	switch {
	case statErr == nil:
		errs = errors.Join(errs, fmt.Errorf("%w: %s", errBPFDirExists, BPFDir))
	case errors.Is(statErr, fs.ErrNotExist):
		// Directory is gone, as expected.
	default:
		errs = errors.Join(errs, fmt.Errorf("stat BPF pin dir: %w", statErr))
	}

	attaches, err := a.bpftoolCgroupShow()
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("cannot verify cgroup attachments: %w", err))
	} else {
		for _, att := range CgroupAttach() {
			if slices.Contains(attaches, att) {
				errs = errors.Join(errs, fmt.Errorf("%w: %s", errProgAttached, att.ProgName))
			}
		}
	}

	return errs
}

func (a *app) isBPFMounted() bool {
	return a.ExecCommand("mountpoint", "-q", BPFRoot).Run() == nil
}

func (a *app) mountBPF() ([]byte, error) {
	return a.ExecCommand("mount", "-t", "bpf", "bpf", BPFRoot).CombinedOutput()
}

func (a *app) bpftoolLoadAll(bpfObjPath string) error {
	out, err := a.ExecCommand("bpftool", "prog", "loadall",
		bpfObjPath, BPFDir, "pinmaps", BPFDir+"/maps",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w\n%s", err, out)
	}
	return nil
}

func (a *app) bpftoolAttach(attachType, progPin string) error {
	return a.ExecCommand("bpftool", "cgroup", "attach",
		CgroupRoot, attachType, "pinned", progPin,
	).Run()
}

func (a *app) bpftoolDetach(attachType, progPin string) error {
	return a.ExecCommand("bpftool", "cgroup", "detach",
		CgroupRoot, attachType, "pinned", progPin,
	).Run()
}

func (a *app) bpftoolMapUpdateMark(m Mark) error {
	leBytes := m.ToLE()
	return a.ExecCommand("bpftool", "map", "update",
		"pinned", BPFDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", leBytes[0], leBytes[1], leBytes[2], leBytes[3],
	).Run()
}

func (a *app) bpftoolCgroupShow() ([]CgroupAttachEntry, error) {
	out, err := a.ExecCommand("bpftool", "--json", "cgroup", "show", CgroupRoot).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return nil, nil
		}
		return nil, err
	}
	var attaches []CgroupAttachEntry
	err = json.Unmarshal(out, &attaches)
	if err != nil {
		return nil, fmt.Errorf("parse bpftool cgroup: %w", err)
	}
	return attaches, nil
}
