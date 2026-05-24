// Package worldcmds provides typed command dispatch for testing
// ExecCommand dispatching without changing app.go.
package worldcmds

//go:generate go-mockgen -f --for-test --prefix Stub -o ../stub.$GOFILE -i WorldCmds .

// WorldCmds provides typed methods for commands that ExecCommand dispatches to.
// Each method models one specific command with its natural return type.
type WorldCmds interface {
	Mountpoint(dir string) error
	MountBPF(fstype, target string) ([]byte, error)
	BpftoolProgLoadAll(bpfObjPath, bpffs, mapsDir string) ([]byte, error)
	BpftoolCgroupAttach(cgroup, attachType, progPin string) error
	BpftoolCgroupDetach(cgroup, attachType, progPin string) error
	BpftoolMapUpdate(args ...string) error
	BpftoolCgroupShow(cgroup string) ([]byte, error)
}
