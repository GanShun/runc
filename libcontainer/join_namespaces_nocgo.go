//go:build linux && !cgo

package libcontainer

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/sirupsen/logrus"
)

// joinNamespaces joins the namespaces the container is given by path.
//
// With cgo this is the C constructor's job (libcontainer/nsenter/nsexec.c). It
// runs before the Go runtime starts, so the process is single-threaded by
// construction, and that timing is what setns(2) wants. Without cgo there is no
// constructor, so the init process does it here instead. Init has already called
// runtime.GOMAXPROCS(1) and runtime.LockOSThread, so this runs on the single
// thread that goes on to do all the container setup and then execs the
// container process; the runtime's other threads run no Go code and are
// destroyed by that exec.
//
// The kernel decides what may be joined this way per namespace type, and the
// ones a pod actually uses are all allowed:
//
//   - network, ipc and uts have no restriction. This is the case that matters:
//     the CRI gives a pod container exactly those three by path
//     (WithPodNamespaces in containerd's internal/cri/opts/spec_opts.go).
//   - mount and cgroup have no restriction either.
//   - a user namespace cannot be joined at all: userns_install() returns EINVAL
//     unless the caller's thread group is empty, and a Go process always has at
//     least the runtime's sysmon thread.
//   - a PID namespace cannot be joined by a single setns(2): it only applies to
//     children created afterwards, so nsexec forks and lets the child become
//     PID 1. There is no way to fork and keep running Go code, so that staging
//     cannot be reproduced here.
//
// The two that cannot be done are refused rather than skipped. Skipping is what
// this build used to do for all of them, and the effect was a container running
// in the host's namespaces while everything above it believed otherwise.
func joinNamespaces(it initType, paths []string) error {
	for _, entry := range paths {
		name, path, ok := strings.Cut(entry, ":")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("invalid namespace path %q", entry)
		}
		switch name {
		case configs.NsName(configs.NEWUSER):
			return fmt.Errorf("joining a user namespace by path is not supported without cgo (%s)", path)
		case configs.NsName(configs.NEWPID):
			if it != initSetns {
				return fmt.Errorf("joining a PID namespace by path is not supported without cgo (%s)", path)
			}
			// runc exec: nsexec would join this by forking so that the new
			// process lands in the container's PID namespace. Without that
			// staging the process still gets every other namespace the
			// container has, so this is skipped rather than refused, which
			// would take out exec probes and kubectl exec entirely.
			logrus.Warnf("not joining PID namespace %s: not supported without cgo", path)
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s namespace %s: %w", name, path, err)
		}
		err = unix.Setns(fd, 0)
		unix.Close(fd)
		if err != nil {
			return fmt.Errorf("setns into %s namespace %s: %w", name, path, err)
		}
	}
	return nil
}
