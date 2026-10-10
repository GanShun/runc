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

// puregoNamespaces is true when runc is built without cgo. In that build the C
// namespace constructor (libcontainer/nsenter) does not exist, so the
// namespaces are created by the Go runtime's clone(2) support in exec.Cmd.
const puregoNamespaces = true

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

const (
	// runcNsHelper is the name the exec staging helper is looked up under on
	// PATH; runcNsHelperEnv overrides it.
	runcNsHelper = "runc-ns"
	// runcNsHelperEnv names an alternative helper, for a build that has it
	// somewhere PATH does not reach.
	runcNsHelperEnv = "RUNC_NS"
	// runcNsReportFdEnv names the descriptor the helper writes the exec'd
	// process's host PID to. It is an independent string literal on each side
	// -- here and in the helper's own reportFdEnv -- so renaming one without
	// the other is a silent protocol break: the parent reads EOF and the exec
	// fails with nothing to say the name is why.
	runcNsReportFdEnv = "_LIBCONTAINER_RUNCNS_PIDFD"
)

// stageExecNs rewrites cmd so that this exec is staged into the container's PID
// namespace by the runc-ns helper, and returns the parent and child ends of the
// pipe the helper reports the exec'd process's host PID on, alongside the
// namespace paths the init stage still has to join itself.
//
// Why a fork is needed at all: setns(CLONE_NEWPID) does not move the caller. It
// sets nsproxy->pid_ns_for_children (kernel/pid_namespace.c: pidns_install), so
// only the caller's next child is created in the container's PID namespace, and
// execve(2) creates no process. runc-ns is that child-creating step, with an
// execve where nsexec has its second fork: it arms pid_ns_for_children, starts
// "runc init" with os/exec on the same locked OS thread, and reports the new
// process's PID. Everything else -- the other namespaces, the rootfs, seccomp,
// the sync protocol -- stays runc init's job, exactly as it is today.
//
// The PID path is removed from the list the init stage is given, because by the
// time runc init exists it is already in that namespace; leaving it in would
// only make joinNamespaces warn about skipping it.
//
// The helper and the pipe are only set up when the container actually has a PID
// namespace to join. With no PID namespace there is nothing to stage, and the
// direct child stays runc init.
func stageExecNs(cmd *exec.Cmd, paths []string) (reportParent, reportChild *os.File, rest []string, err error) {
	rest, pidPath := splitPidNamespacePath(paths)
	if pidPath == "" {
		return nil, nil, paths, nil
	}

	helper, err := findRuncNs()
	if err != nil {
		return nil, nil, nil, err
	}

	// The path the helper execs. It is the same path runc would have exec'd
	// itself, and it resolves inside the helper because the descriptor
	// numbering does not change across one more exec -- except for the one
	// case where it names /proc/self/exe, which inside the helper would be the
	// helper. There, the binary is handed over as a descriptor instead.
	initExe := cmd.Path
	if initExe == "/proc/self/exe" {
		self, err := os.Open("/proc/self/exe")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open /proc/self/exe for runc-ns: %w", err)
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, self)
		initExe = "/proc/self/fd/" + strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1)
	}

	reportParent, reportChild, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("unable to create the runc-ns pid report pipe: %w", err)
	}

	// Appended last, so that every descriptor index computed above -- and every
	// _LIBCONTAINER_* variable that names one -- is unchanged.
	cmd.ExtraFiles = append(cmd.ExtraFiles, reportChild)
	cmd.Env = append(cmd.Env, runcNsReportFdEnv+"="+strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1))

	// The helper is invoked as
	//   runc-ns <pid-ns-path> <runc> <runc argv0> init [args...]
	// and execs its own argv[2:] with argv[2] as Path. Passing runc's argv[0]
	// separately from the path is what lets the exec'd runc init keep the
	// argv[0] it would have had as a direct child of runc rather than seeing
	// the descriptor path as its own name.
	runcArgv0 := cmd.Args[0]
	cmd.Args = append([]string{helper, pidPath, initExe, runcArgv0}, cmd.Args[1:]...)
	cmd.Path = helper

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

// findRuncNs locates the runc-ns helper.
func findRuncNs() (string, error) {
	name := os.Getenv(runcNsHelperEnv)
	if name == "" {
		name = runcNsHelper
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("unable to find the %s exec helper (set %s to point at one): %w",
			name, runcNsHelperEnv, err)
	}
	return path, nil
}
