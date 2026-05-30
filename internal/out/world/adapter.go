//nolint:godoclint,revive // Thin wrappers over standard library functions.
package world

import (
	"os"
	"os/exec"

	"github.com/powerman/ebpf-same-cgroup-mark/internal/app"
)

// RealWorld implements [app.World] with real OS and exec calls.
type RealWorld struct{}

func (RealWorld) Mountpoint(dir string) error {
	return exec.Command("mountpoint", "-q", dir).Run() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) MountBPF(fstype, target string) ([]byte, error) {
	return exec.Command("mount", "-t", "bpf", "bpf", target).CombinedOutput() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) BpftoolProgLoadAll(bpfObjPath, bpffs, mapsDir string) ([]byte, error) {
	return exec.Command("bpftool", "prog", "loadall", bpfObjPath, bpffs, "pinmaps", mapsDir).CombinedOutput() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) BpftoolCgroupAttach(cgroup, attachType, progPin string) error {
	return exec.Command("bpftool", "cgroup", "attach", cgroup, attachType, "pinned", progPin).Run() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) BpftoolCgroupDetach(cgroup, attachType, progPin string) error {
	return exec.Command("bpftool", "cgroup", "detach", cgroup, attachType, "pinned", progPin).Run() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) BpftoolMapUpdate(args ...string) error {
	return exec.Command("bpftool", args...).Run() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) BpftoolCgroupShow(cgroup string) ([]byte, error) {
	return exec.Command("bpftool", "--json", "cgroup", "show", cgroup).Output() //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) OsCreateTemp(dir, pattern string) (app.WorldOsFile, error) {
	return os.CreateTemp(dir, pattern)
}

func (RealWorld) OsGeteuid() int                                 { return os.Geteuid() }
func (RealWorld) OsMkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (RealWorld) OsRemoveAll(path string) error                  { return os.RemoveAll(path) }
func (RealWorld) OsRemove(name string) error                     { return os.Remove(name) }
func (RealWorld) OsStat(name string) (os.FileInfo, error)        { return os.Stat(name) }
