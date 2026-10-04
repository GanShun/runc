//go:build linux && cgo

package libcontainer

import "os/exec"

// puregoNamespaces is false for the normal (cgo) build: the C constructor in
// libcontainer/nsenter creates the namespaces before the Go runtime starts,
// and reports the final child PID over the init pipe.
const puregoNamespaces = false

// setCloneFlags is a no-op for the cgo build; the C constructor owns this.
func setCloneFlags(cmd *exec.Cmd, flags uintptr) {}
