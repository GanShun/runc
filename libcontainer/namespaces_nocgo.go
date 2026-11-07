//go:build linux && !cgo

package libcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// parentCreatesNamespaces is true when runc is built without cgo. In that build the C
// namespace constructor (libcontainer/nsenter) does not exist, so the
// namespaces are created by the Go runtime's clone(2) support in exec.Cmd.
const parentCreatesNamespaces = true

// setCloneFlags asks the kernel to create the container's namespaces directly
// when the init process is cloned. This replaces what nsexec.c does before the
// Go runtime starts.
//
// A user namespace cannot be combined with the others in a single clone(2) --
// the kernel returns EPERM -- which is the ordering nsexec works around; that
// case is not handled here.
//
// The caller must only use this for the container's own init. An exec child is
// not cloned into new namespaces: it joins the container's by setns, and
// CloneFlags() is a flag for every private namespace the container has (see
// Namespaces.CloneFlags), so applying it to an exec child would put it in
// brand-new net/ipc/uts/mnt/cgroup namespaces -- and in a brand-new PID
// namespace, from which the container's own could then not be reached, because
// pidns_install only accepts a descendant of the caller's active namespace.
func setCloneFlags(cmd *exec.Cmd, flags uintptr) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &unix.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags = flags
}

// stageExecNs rewrites cmd so that this exec is staged into the container's PID
// namespace by RuncNsCommand, and returns the parent and child ends of the pipe
// that stage reports the exec'd process's host PID on, alongside the namespace
// paths the init stage still has to join itself.
//
// Why a fork is needed at all: setns(CLONE_NEWPID) does not move the caller. It
// sets nsproxy->pid_ns_for_children (kernel/pid_namespace.c: pidns_install), so
// only the caller's next child is created in the container's PID namespace, and
// execve(2) creates no process. The stage is that child-creating step, with an
// execve where nsexec has its second fork: it arms pid_ns_for_children, starts
// "runc init" with os/exec on the same locked OS thread, and reports the new
// process's PID. Everything else -- the other namespaces, the rootfs, seccomp,
// the sync protocol -- stays runc init's job, exactly as it is today.
//
// The PID path is removed from the list the init stage is given, because by the
// time runc init exists it is already in that namespace; leaving it in would
// only make joinNamespaces refuse it.
//
// The stage and the pipe are only set up when the container actually has a PID
// namespace to join. With no PID namespace there is nothing to stage, and the
// direct child stays runc init.
func stageExecNs(cmd *exec.Cmd, paths []string) (reportParent, reportChild *os.File, rest []string, err error) {
	return stageNs(cmd, paths, 0)
}

// stageInitNs is stageExecNs for the container's own init, and differs in what the
// stage must do with the clone(2) that creates the process.
//
// An exec child joins every namespace by setns and takes none of its own, so the
// stage clones it with CLONE_PARENT alone. A container's init owns its private
// namespaces: with cgo, nsexec's stage 2 creates them and forks stage 3 in. Here
// the stage's clone(2) is that fork, so the init's clone flags travel down to it —
// and they must, because that clone is the only thing that creates a process
// inside the PID namespace that was just joined. The stage itself keeps runc's
// namespaces; that is what makes the setns target reachable.
//
// The parent-death signal is the exception: it is *not* passed down, because Go's
// fork code kills a child whose getppid() differs from the forking process's pid and
// CLONE_PARENT makes that always true. A config that asks for one is refused before
// it gets this far (checkNocgoConfig); stagedSysProcAttr has the whole of it.
func stageInitNs(cmd *exec.Cmd, paths []string, cloneFlags uintptr) (reportParent, reportChild *os.File, rest []string, err error) {
	return stageNs(cmd, paths, cloneFlags)
}

// stageNs is the staging both callers above need: it takes the PID namespace path
// out of the list the init stage would join, points cmd at RuncNsCommand, and
// hands back the report pipe when there is something to stage.
func stageNs(cmd *exec.Cmd, paths []string, cloneFlags uintptr) (reportParent, reportChild *os.File, rest []string, err error) {
	rest, pidPath := splitPidNamespacePath(paths)
	if pidPath == "" {
		return nil, nil, paths, nil
	}

	// The stage must not be cloned into the container's namespaces: it has to
	// reach the PID namespace by path with setns(2), and it cannot do that from
	// inside a namespace it is also creating. An exec child never had any here;
	// an init's were applied to cmd by newParentProcess, so they are moved to the
	// environment for the stage's own clone.
	if cmd.SysProcAttr != nil {
		if cloneFlags != 0 {
			cmd.SysProcAttr.Cloneflags = 0
		}
		// The stage is runc's direct child, so a parent-death signal on it would
		// work -- and be pointless, since it exits immediately. Nothing else arms
		// one either: checkNocgoConfig refuses the config that asks for it.
		cmd.SysProcAttr.Pdeathsig = 0
	}
	if cloneFlags != 0 {
		cmd.Env = append(cmd.Env, runcNsCloneFlagsEnv+"="+strconv.FormatUint(uint64(cloneFlags), 10))
	}

	reportParent, reportChild, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create the %s pid report pipe: %w", RuncNsCommand, err)
	}

	// Appended last, so that every descriptor index computed above -- and every
	// _LIBCONTAINER_* variable that names one -- is unchanged.
	cmd.ExtraFiles = append(cmd.ExtraFiles, reportChild)
	cmd.Env = append(cmd.Env, runcNsReportFdEnv+"="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1))

	// The stage is invoked as
	//   runcns <pid-ns-path> <runc> <runc argv0> init [args...]
	// and execs its own args[1:] with args[1] as Path. Passing runc's argv[0]
	// separately from the path is what lets the exec'd runc init keep the
	// argv[0] it would have had as a direct child of runc rather than seeing
	// the descriptor path as its own name.
	//
	// Both this stage and the init stage that follows it are exec'd from
	// cmd.Path, the path runc built for its own child. It names a sealed copy of
	// this binary through /proc/self/fd/N, or /proc/self/exe when that copy
	// already exists, and it is the only path that resolves in both cases:
	// os.Executable() names a /memfd: while runc is running from its own clone,
	// which is not on disk, so the stage would fail with ENOENT. Taking the
	// stage from the sealed copy is also what makes it the same binary as the
	// runc that started it even when runc is replaced on disk mid-exec.
	//
	// The path stays valid across this one extra exec: safeExe is in ExtraFiles,
	// so it is not close-on-exec, and its number does not change when the report
	// pipe is appended after it.
	//
	// argv[0] is runc's own, not the descriptor path: dispatch reads os.Args[1],
	// so the name is only what an operator sees in ps, and "/proc/self/fd/3
	// runcns ..." says less about what is running than "runc runcns ..." does.
	initExe := cmd.Path
	runcArgv0 := cmd.Args[0]
	cmd.Args = append([]string{runcArgv0, RuncNsCommand, pidPath, initExe, runcArgv0}, cmd.Args[1:]...)
	cmd.Path = initExe

	return reportParent, reportChild, rest, nil
}

// splitPidNamespacePath takes the PID namespace out of the "<name>:<path>"
// entries orderNamespacePaths produced, returning the rest and the path.
func splitPidNamespacePath(paths []string) (rest []string, pidPath string) {
	rest = make([]string, 0, len(paths))
	for _, entry := range paths {
		if name, path, ok := strings.Cut(entry, ":"); ok && name == configs.NsName(configs.NEWPID) {
			pidPath = path
			continue
		}
		rest = append(rest, entry)
	}
	return rest, pidPath
}

// checkNocgoConfig refuses configuration this build cannot honour.
//
// The time-namespace offsets travel in the netlink bootstrap payload, which only
// the C constructor reads, so the clone(2) that creates the namespace here makes
// one with zero offsets and the container silently gets the host's clocks.
// Silently is the problem: the caller asked for a shifted clock, and nothing in
// the container would show that it did not get one.
//
// The parent-death signal cannot be honoured either, and for a reason that does
// not depend on the staging: Go forks the container's init from whichever runc
// thread called cmd.Start, and PR_SET_PDEATHSIG follows that thread, so the Go
// runtime retiring it would kill a container whose runc is still running
// (golang/go#27505). Upstream runc honours the field anyway; this build refuses
// it rather than deliver a signal that means something other than the caller
// asked for.
func checkNocgoConfig(config *configs.Config) error {
	if config.ParentDeathSignal > 0 {
		return fmt.Errorf("ParentDeathSignal cannot be honoured without cgo: the container's parent is a runc thread, which the Go runtime may retire at any time (golang/go#27505)")
	}
	// len, not nil: specconv copies spec.Linux.TimeOffsets straight through, so a
	// spec carrying "timeOffsets": {} arrives as an empty non-nil map and asks
	// for nothing.
	if len(config.TimeOffsets) > 0 {
		return fmt.Errorf("timeOffsets cannot be applied without cgo: only the C namespace constructor reads them, so the time namespace would be created with none")
	}
	return nil
}
