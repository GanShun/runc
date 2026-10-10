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
//   - network, ipc and uts have no restriction. This is the case that matters
//     for a container's own init: the CRI gives a pod container exactly those
//     three by path (WithPodNamespaces in containerd's
//     internal/cri/opts/spec_opts.go).
//   - cgroup has no restriction either.
//   - mount has one, and it is the reason an exec ever failed here:
//     mntns_install() returns EINVAL when the caller's fs_struct is shared
//     (fs/namespace.c: fs->users != 1), because a lone setns(CLONE_NEWNS)
//     rewrites the caller's own fs rather than a copy (kernel/nsproxy.c:
//     prepare_nsset sets nsset->fs = me->fs for exactly that flag). Every
//     thread of a Go process shares one fs_struct -- the runtime clones them
//     with CLONE_FS (runtime/os_linux.go) -- so joining a mount namespace needs
//     detachFs first.
//   - a user namespace cannot be joined at all: userns_install() returns EINVAL
//     unless the caller's thread group is empty, and a Go process always has at
//     least the runtime's sysmon thread.
//   - a PID namespace cannot be joined by a single setns(2): it only applies to
//     children created afterwards (kernel/pid_namespace.c: pidns_install sets
//     nsproxy->pid_ns_for_children and returns, it does not move the caller), so
//     nsexec forks and lets the child be created there. A raw fork that carries
//     on running Go is not available, but a fork that re-execs is: cmd/runc-ns,
//     which arms pid_ns_for_children and then starts the init stage with
//     os/exec (see stageExecNs in purego_nocgo.go). An exec therefore never
//     reaches this branch with a PID path: the path is handed to that helper
//     and taken out of the list below.
//
// The two that cannot be done are refused rather than skipped. Skipping is what
// this build used to do for all of them, and the effect was a container running
// in the host's namespaces while everything above it believed otherwise.
//
// Every descriptor is opened before any of them is joined, which is what
// nsexec's join_namespaces does and for the same reason (nsexec.c:641-651):
// "We have to open the file descriptors first, since after we join the mnt or
// user namespaces we might no longer be able to access the paths." A namespace
// path names a host pid, and the moment the mount namespace is joined /proc is
// the container's procfs -- a procfs for the container's own PID namespace, in
// which the host pids the remaining paths refer to do not exist, so the open
// fails with ENOENT. Opening first makes the order of the joins irrelevant,
// which is what `runc exec` needs: it is the path with a mount namespace in the
// list.
func joinNamespaces(it initType, paths []string) error {
	type nsFd struct {
		name string
		path string
		fd   int
	}

	// Kept open until the end rather than closed as each one is joined: closing
	// an fd here would let the Go runtime reuse the number, and this is a
	// process whose other threads are still running. They are O_CLOEXEC, so
	// they cannot leak into the container process either way.
	toJoin := make([]nsFd, 0, len(paths))
	defer func() {
		for _, ns := range toJoin {
			_ = unix.Close(ns.fd)
		}
	}()

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
			// Reached only if the PID path was not taken out of the list before
			// the init stage was started, which is what stageExecNs does. The
			// process still gets every other namespace the container has, so
			// skipping beats refusing -- refusing would take out exec probes
			// and kubectl exec as well -- but it is a real loss of isolation,
			// so it says so.
			logrus.Warnf("not joining PID namespace %s: not staged by runc-ns, so the process will be in the host's PID namespace", path)
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s namespace %s: %w", name, path, err)
		}
		toJoin = append(toJoin, nsFd{name: name, path: path, fd: fd})
	}

	for _, ns := range toJoin {
		if ns.name == configs.NsName(configs.NEWNS) {
			if err := detachFs(); err != nil {
				return err
			}
		}
		if err := unix.Setns(ns.fd, 0); err != nil {
			return fmt.Errorf("setns into %s namespace %s: %w", ns.name, ns.path, err)
		}
	}
	return nil
}

// detachFs gives the calling thread an fs_struct of its own, which is what
// makes a mount namespace joinable at all from a Go process.
//
// mntns_install refuses when the caller's fs_struct is shared, because a lone
// setns(CLONE_NEWNS) rewrites that fs in place instead of a temporary copy, and
// every thread of a Go process shares one fs_struct by construction: the runtime
// creates threads with CLONE_FS (runtime/os_linux.go:
// "_CLONE_FS | /* share cwd, etc */"). unshare(CLONE_FS) gives this task a copy
// with users == 1 and drops it from the shared one; the kernel returns without
// doing anything if the fs is already unshared, so this is idempotent.
//
// It has to be the thread locked in Init -- the one that goes on to exec the
// container process -- and it must not be undone, because the fs this thread
// gets is the one the mount namespace install then rewrites with the
// container's root and working directory. The runtime's other threads keep the
// fs_struct they already had, so nothing else is affected.
//
// goCreateMountSources does exactly this pair, for exactly this reason, on its
// own locked thread (process_linux.go: "Detach from the shared fs of the rest
// of the Go process in order to be able to CLONE_NEWNS").
func detachFs() error {
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare(CLONE_FS) to be able to join a mount namespace: %w", err)
	}
	return nil
}
