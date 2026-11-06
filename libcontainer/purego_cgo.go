//go:build linux && cgo

package libcontainer

import (
	"os"
	"os/exec"
)

// puregoNamespaces is false for the normal (cgo) build: the C constructor in
// libcontainer/nsenter creates the namespaces before the Go runtime starts,
// and reports the final child PID over the init pipe.
const puregoNamespaces = false

// setCloneFlags is a no-op for the cgo build; the C constructor owns this.
func setCloneFlags(cmd *exec.Cmd, flags uintptr) {}

// stageExecNs is a no-op for the cgo build: nsexec's stage 1 joins every
// namespace, including the PID namespace, and its second fork
// (libcontainer/nsenter/nsexec.c:1132) is what puts stage 2 in it. Nothing is
// rewritten, and the parent keeps reading the stage1/stage2 pid JSON.
func stageExecNs(cmd *exec.Cmd, paths []string) (*os.File, *os.File, []string, error) {
	return nil, nil, paths, nil
}
