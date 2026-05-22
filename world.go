//go:generate mise exec -- sh -c "mockgen -package=\"${DOLLAR}1_test\" -source=\"${DOLLAR}2\" -destination=\"mock.$(basename \"${DOLLAR}2\" .go)_test.go\"" _ $GOPACKAGE $GOFILE

//nolint:godoclint // Thin wrappers over standard library functions.
package main

import (
	"os"
	"os/exec"
)

// World abstracts OS and exec dependencies for testability.
type World interface {
	ExecCommand(name string, args ...string) WorldExecCmd
	OsCreateTemp(dir, pattern string) (WorldOsFile, error)
	OsGeteuid() int
	OsMkdirAll(path string, perm os.FileMode) error
	OsRemoveAll(path string) error
	OsStat(name string) (os.FileInfo, error)
}

// WorldExecCmd abstracts the result of an executed command.
type WorldExecCmd interface {
	CombinedOutput() ([]byte, error)
	Run() error
}

// WorldOsFile allows mocking [os.File] operations in tests.
type WorldOsFile interface {
	Close() error
	Name() string
	Write(p []byte) (n int, err error)
}

// RealWorld implements World with real OS and exec calls.
type RealWorld struct{}

func (RealWorld) ExecCommand(name string, args ...string) WorldExecCmd {
	return exec.Command(name, args...) //nolint:gosec,noctx // False positive; timeout not needed.
}

func (RealWorld) OsCreateTemp(dir, pattern string) (WorldOsFile, error) {
	return os.CreateTemp(dir, pattern)
}

func (RealWorld) OsGeteuid() int                                 { return os.Geteuid() }
func (RealWorld) OsMkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (RealWorld) OsRemoveAll(path string) error                  { return os.RemoveAll(path) }
func (RealWorld) OsStat(name string) (os.FileInfo, error)        { return os.Stat(name) }
