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
	World

	Mark string `help:"Mark mask (e.g. 0x40000000)." short:"m"`
}

func (c *loadCmd) Run(world World) error {
	c.World = world

	err := rootCheck(c.World)
	if err != nil {
		return err
	}

	_ = unload(c.World)

	bpfObjPath, err := c.writeTempBPFObj()
	if err != nil {
		return err
	}
	//nolint:errcheck // cleanup on best-effort basis
	defer os.Remove(bpfObjPath)

	err = c.ensureBPFFS()
	if err != nil {
		return err
	}

	err = c.OsRemoveAll(pinDir)
	if err != nil {
		return fmt.Errorf("cleanup old pin dir: %w", err)
	}

	err = run(c.World, "bpftool", "prog", "loadall",
		bpfObjPath, pinDir,
		"pinmaps", pinDir+"/maps",
	)
	if err != nil {
		return fmt.Errorf("bpftool loadall: %w", err)
	}

	for _, a := range cgroupAttach() {
		progPin := filepath.Join(pinDir, a.progName)
		err = run(c.World, "bpftool", "cgroup", "attach",
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
		err = c.setMark(mark)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *loadCmd) setMark(mark uint32) error {
	leBytes := markToLE(mark)

	err := run(c.World, "bpftool", "map", "update",
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

func (c *loadCmd) ensureBPFFS() error {
	err := c.OsMkdirAll("/sys/fs/bpf", bpffsMode)
	if err != nil {
		return err
	}
	err = run(c.World, "mountpoint", "-q", "/sys/fs/bpf")
	if err == nil {
		return nil
	}
	out, err := c.CmdOutput("mount", "-t", "bpf", "bpf", "/sys/fs/bpf")
	if err != nil {
		return fmt.Errorf("mount bpf: %w\n%s", err, out)
	}
	return nil
}

func (c *loadCmd) writeTempBPFObj() (string, error) {
	f, err := c.OsCreateTemp("", "same-cgroup-mark.*.bpf.o")
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

type unloadCmd struct {
	World
}

func (c *unloadCmd) Run(world World) error {
	c.World = world

	err := rootCheck(c.World)
	if err != nil {
		return err
	}

	return unload(c.World)
}

func rootCheck(w World) error {
	if w.OsGeteuid() != 0 {
		return errMustBeRoot
	}

	return nil
}

func unload(w World) error {
	_, err := w.OsStat(pinDir)
	if os.IsNotExist(err) {
		return nil
	}

	for _, a := range cgroupAttach() {
		progPin := filepath.Join(pinDir, a.progName)
		_ = run(w, "bpftool", "cgroup", "detach",
			cgroupPath, a.attachType, "pinned", progPin,
		)
	}

	return w.OsRemoveAll(pinDir)
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

func run(w World, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bpfTimeout)
	defer cancel()

	return w.CmdRun(ctx, args[0], args[1:]...)
}
