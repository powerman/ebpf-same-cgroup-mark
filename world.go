//go:generate mise exec -- mockgen -package=$GOPACKAGE -source=$GOFILE -destination=mock.$GOFILE -write_package_comment=false

//nolint:godoclint // Thin wrappers over standard library functions.
package main

import (
	"context"
	"os"
	"os/exec"
)

// World abstracts OS and exec dependencies for testability.
type World interface {
	CmdRun(ctx context.Context, name string, args ...string) error
	CmdOutput(name string, args ...string) ([]byte, error)
	OsCreateTemp(dir, pattern string) (TempFile, error)
	OsGeteuid() int
	OsMkdirAll(path string, perm os.FileMode) error
	OsRemoveAll(path string) error
	OsStat(name string) (os.FileInfo, error)
}

// RealWorld implements World with real OS and exec calls.
type RealWorld struct{}

func (RealWorld) CmdRun(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // False positive.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (RealWorld) CmdOutput(name string, args ...string) ([]byte, error) {
	return exec.CommandContext(context.Background(), name, args...).CombinedOutput() //nolint:gosec // False positive.
}

// TempFile allows mocking [os.File] operations in tests.
type TempFile interface {
	Write(p []byte) (n int, err error)
	Close() error
	Name() string
}

func (RealWorld) OsCreateTemp(dir, pattern string) (TempFile, error) {
	return os.CreateTemp(dir, pattern)
}

func (RealWorld) OsGeteuid() int                                 { return os.Geteuid() }
func (RealWorld) OsMkdirAll(path string, perm os.FileMode) error { return os.MkdirAll(path, perm) }
func (RealWorld) OsRemoveAll(path string) error                  { return os.RemoveAll(path) }
func (RealWorld) OsStat(name string) (os.FileInfo, error)        { return os.Stat(name) }
