// Binary to load/unload eBPF program that sets SO_MARK on same-cgroup TCP
// connections.
package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed .cache/same-cgroup-mark.bpf.o
var bpfObj []byte

const (
	pinDir     = "/sys/fs/bpf/same-cgroup-mark"
	cgroupPath = "/sys/fs/cgroup"
	bpffsMode  = fs.FileMode(0o750)
	bpfTimeout = 10 * time.Second
)

var (
	errMustBeRoot   = errors.New("must be run as root")
	errMarkOverflow = errors.New("mark value exceeds 32-bit maximum (0xFFFFFFFF)")
)

type loadCmd struct {
	Mark string `help:"Mark mask (e.g. 0x40000000)." short:"m"`
}

func (c *loadCmd) Run(_ *cliContext) error {
	err := rootCheck()
	if err != nil {
		return err
	}

	_ = unload()

	bpfObjPath, err := writeTempBPFObj()
	if err != nil {
		return err
	}
	//nolint:errcheck // cleanup on best-effort basis
	defer os.Remove(bpfObjPath)

	err = ensureBPFFS()
	if err != nil {
		return err
	}

	err = os.RemoveAll(pinDir)
	if err != nil {
		return fmt.Errorf("cleanup old pin dir: %w", err)
	}

	err = run("bpftool", "prog", "loadall",
		bpfObjPath, pinDir,
		"pinmaps", pinDir+"/maps",
	)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, a := range cgroupAttach() {
		progPin := filepath.Join(pinDir, a.progName)
		err = run("bpftool", "cgroup", "attach",
			cgroupPath, a.attachType, "pinned", progPin,
		)
		if err != nil {
			return fmt.Errorf("attach %s: %w", a.progName, err)
		}
	}

	if c.Mark != "" {
		mark, err := parseMark(c.Mark)
		if err != nil {
			return err
		}
		err = setMark(mark)
		if err != nil {
			return err
		}
	}

	return nil
}

type unloadCmd struct{}

func (*unloadCmd) Run(_ *cliContext) error {
	err := rootCheck()
	if err != nil {
		return err
	}

	return unload()
}

func rootCheck() error {
	if os.Geteuid() != 0 {
		return errMustBeRoot
	}

	return nil
}

func unload() error {
	_, err := os.Stat(pinDir)
	if os.IsNotExist(err) {
		return nil
	}

	for _, a := range cgroupAttach() {
		progPin := filepath.Join(pinDir, a.progName)
		_ = run("bpftool", "cgroup", "detach",
			cgroupPath, a.attachType, "pinned", progPin,
		)
	}

	return os.RemoveAll(pinDir)
}

type cgroupAttachEntry struct {
	progName, attachType string
}

func cgroupAttach() []cgroupAttachEntry {
	return []cgroupAttachEntry{
		{"same_cgroup_bind4", "cgroup_inet4_bind"},
		{"same_cgroup_bind6", "cgroup_inet6_bind"},
		{"same_cgroup_connect4", "cgroup_inet4_connect"},
		{"same_cgroup_connect6", "cgroup_inet6_connect"},
	}
}

func setMark(mark uint32) error {
	leBytes := markToLE(mark)

	err := run("bpftool", "map", "update",
		"pinned", pinDir+"/maps/same_cgroup_mark_cfg",
		"key", "hex", "00", "00", "00", "00",
		"value", "hex", leBytes[0], leBytes[1], leBytes[2], leBytes[3],
	)
	if err != nil {
		return fmt.Errorf("set mark: %w", err)
	}
	fmt.Printf("Mark mask set to 0x%08x\n", mark)
	return nil
}

func markToLE(mark uint32) [4]string {
	hex := fmt.Sprintf("%08x", mark)
	return [4]string{hex[6:8], hex[4:6], hex[2:4], hex[0:2]}
}

func parseMark(s string) (uint32, error) {
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var v uint64
	_, err := fmt.Sscanf(s, "%x", &v)
	if err != nil {
		return 0, fmt.Errorf("invalid mark value %q: %w", s, err)
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("%w: 0x%X", errMarkOverflow, v)
	}
	return uint32(v), nil
}

func ensureBPFFS() error {
	err := os.MkdirAll("/sys/fs/bpf", bpffsMode)
	if err != nil {
		return err
	}
	//nolint:noctx // simple mountpoint check, no external request
	err = exec.Command("mountpoint", "-q", "/sys/fs/bpf").Run()
	if err == nil {
		return nil
	}
	//nolint:noctx // simple mount command, no external request
	out, err := exec.Command("mount", "-t", "bpf", "bpf", "/sys/fs/bpf").CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount bpffs: %w\n%s", err, out)
	}
	return nil
}

func writeTempBPFObj() (string, error) {
	f, err := os.CreateTemp("", "same-cgroup-mark-*.bpf.o")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	_, err = f.Write(bpfObj)
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

//nolint:gosec // args are controlled by the program, not user input
func run(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bpfTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
