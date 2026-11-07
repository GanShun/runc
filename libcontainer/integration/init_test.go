package integration

import (
	"os"
	"testing"

	"github.com/opencontainers/runc/libcontainer"
	//nolint:revive // Enable cgroup manager to manage devices
	_ "github.com/opencontainers/cgroups/devices"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

// Same as ../../init.go but for libcontainer/integration.
//
// The runcns case is not optional here: without cgo, an exec into a container that
// has a PID namespace is staged by re-executing this binary as
// `<argv0> runcns <pid-ns-path> ...`, and a binary that does not dispatch that
// runs the Go test flags against it instead and exits 1. Every exec test then
// fails with "error executing setns process: exit status 1" before reaching
// anything it meant to check.
func init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "init":
		libcontainer.Init()
	case libcontainer.RuncNsCommand:
		libcontainer.RunRuncNs(os.Args[2:])
	}
}

func TestMain(m *testing.M) {
	ret := m.Run()
	os.Exit(ret)
}
