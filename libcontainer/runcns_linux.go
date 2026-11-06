//go:build linux

package libcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// RuncNsCommand is the internal runc subcommand that stages a "runc exec"
// process into the container's PID namespace. It is invoked as
//
//	runc runcns <pid-namespace-path> <program> <argv0> [args...]
//
// and it is a subcommand of this binary rather than a separate helper because
// the stage it starts is a fresh runc: "runc init" is already a re-exec of
// /proc/self/exe, and the C namespace staging nsexec is inside the runc binary
// too, so a Go stage in the same binary is the closer analogue of both. Being
// one binary also means the staging stage and the runc that invokes it cannot
// be different versions, and the report protocol below has one definition
// instead of one per binary.
//
// It is dispatched before the CLI, in the same place as "init" (see the main
// package), so it stays out of the user-facing help and gets no flags.
const RuncNsCommand = "runcns"

// runcNsReportFdEnv names the descriptor this stage writes the exec'd process's
// host PID to: the write end of a pipe the runc performing the exec holds the
// read end of. Both ends of the protocol are in this package, so the name has
// exactly one definition.
const runcNsReportFdEnv = "_LIBCONTAINER_RUNCNS_PIDFD"

// RunRuncNs is the entry point for RuncNsCommand, with args being everything
// after the subcommand name.
//
// It never returns, like Init: it either does its job and exits, or reports the
// reason on stderr and exits non-zero. The caller is the runc binary's dispatch,
// which runs before the CLI and before anything else has touched stderr.
func RunRuncNs(args []string) {
	if err := runRuncNs(args); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", RuncNsCommand, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// runRuncNs stages <program> into the PID namespace at <pid-namespace-path> and
// reports the created process's host PID over the descriptor named by
// runcNsReportFdEnv.
//
// setns(2) cannot put the caller into a PID namespace. pidns_install()
// (kernel/pid_namespace.c:392) stores the target in
// nsproxy->pid_ns_for_children and returns -- the caller does not move, and
// only its *next child* is created there. execve(2) creates no process, so
// "setns, then exec the next stage" cannot join one: the exec'd stage is still
// in the caller's PID namespace. A fork is required, and Go cannot fork and
// keep running Go. It can fork and *re-exec*, which is what os/exec does, and
// the next stage here is a fresh program, so nothing has to survive the fork.
//
// So this is nsexec's stage 1 with an execve in place of the double fork:
//
//  1. setns(CLONE_NEWPID) into the container's PID namespace. That only arms
//     pid_ns_for_children -- see above.
//  2. start the next stage on the same locked OS thread. The clone(2) that
//     os/exec performs is the fork, so the new process is created in the
//     container's PID namespace, and it is "runc init" that then joins the
//     container's other namespaces itself, exactly as it does for a container's
//     own init.
//  3. report that process's host PID to runc, and exit.
//
// The next stage is deliberately made a child of *runc* rather than of this
// process (CLONE_PARENT), exactly as nsexec's clone_parent() does
// (nsexec.c:322). runc reaps the process it exec'd and turns its exit status
// into the exit status of "runc exec": its SIGCHLD loop is a wait4(-1) over its
// own children (signals.go: reap), so a process that is nobody's child would
// never be reported as exited and "runc exec" would hang forever. nsexec says
// the same thing at nsexec.c:930-935, where it asks runc to reap stage 1 for
// it.
//
// Every other file descriptor runc handed over -- the init, sync and log pipes,
// the console and pidfd sockets, any preserved descriptors, and the container's
// stdio -- is inherited by the next stage untouched, because the numbering does
// not change across one more exec and the _LIBCONTAINER_* variables that name
// them are inherited too. Nothing is re-plumbed here, and nothing is inspected.
//
// It never unlocks the OS thread. A LockOSThread goroutine that exits without
// unlocking takes the thread with it, which is what happens here.
func runRuncNs(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: %s <pid-namespace-path> <program> <argv0> [args...]", RuncNsCommand)
	}
	pidNsPath, argv := args[0], args[1:]

	reportFd, err := strconv.Atoi(strings.TrimSpace(os.Getenv(runcNsReportFdEnv)))
	if err != nil {
		return fmt.Errorf("%s: %w", runcNsReportFdEnv, err)
	}

	// setns(CLONE_NEWPID) does not move this process. pidns_install()
	// (kernel/pid_namespace.c:392) writes pid_ns_for_children in the fresh
	// nsproxy prepare_nsset() allocated, and commit_nsset() installs that
	// nsproxy on *the calling task only* (kernel/nsproxy.c:354-366, :565,
	// switch_task_namespaces). So this thread -- and not the process -- is the
	// only one with an armed pid_ns_for_children, and the clone(2) that creates
	// the child has to come from it: os/exec performs that clone on the thread
	// that calls Start. LockOSThread keeps this goroutine on that thread;
	// without it the scheduler could move the goroutine after the setns and the
	// clone would be made by a thread that never did it. Nothing may clone in
	// between either, which is why there is exactly one os/exec call below and
	// no goroutine anywhere in this path.
	runtime.LockOSThread()

	fd, err := unix.Open(pidNsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", pidNsPath, err)
	}
	err = unix.Setns(fd, unix.CLONE_NEWPID)
	unix.Close(fd)
	if err != nil {
		return fmt.Errorf("setns(CLONE_NEWPID, %s): %w", pidNsPath, err)
	}

	return startExecNsStage(argv, reportFd)
}

// startExecNsStage starts the next stage and reports its host PID to runc.
func startExecNsStage(argv []string, reportFd int) error {
	// If anything below fails after the clone, runc must see EOF on the report
	// pipe rather than wait for a pid that will never arrive. Close-on-exec
	// also keeps the descriptor out of the container's process, which is both
	// tidier and what makes a failure after the clone diagnosable instead of a
	// hang.
	unix.CloseOnExec(reportFd)

	cmd := &exec.Cmd{
		// Path is used for execve(2) exactly as given: it is the path runc
		// built for its own child, which is /proc/self/fd/N of a sealed copy of
		// the runc binary (or /proc/self/exe when that copy already exists).
		// The descriptor numbering is unchanged by this one extra process, so
		// the same path still resolves here. exec.Command's LookPath is
		// deliberately skipped: the path is absolute, and when it names an
		// O_PATH descriptor of a sealed memfd there is nothing useful for
		// LookPath to check anyway.
		Path: argv[0],
		// argv[0] is the path and argv[1:] is the child's own argv, whose
		// argv[0] is runc's own argv[0]. Keeping them apart is what lets the
		// exec'd runc init see the same argv[0] a direct child of runc would;
		// using argv here would replace it with the descriptor path.
		Args:   argv[1:],
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		// No Dir, so the child inherits this process's working directory, which
		// runc set to the container's root before starting this stage.
		//
		// Env is left nil, so the child inherits this process's environment --
		// every _LIBCONTAINER_* variable runc set, unexamined.
		SysProcAttr: &syscall.SysProcAttr{
			// The child of this child is runc's, not ours. See runRuncNs.
			Cloneflags: syscall.CLONE_PARENT,
		},
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", argv[0], err)
	}

	// This process's own PID namespace was not changed by the setns above, so
	// the value clone(2) returned is the child's number in *this* process's
	// active namespace -- runc's -- which is the number runc needs.
	// (kernel/fork.c:2761: nr = pid_vnr(pid).)
	report := strconv.Itoa(cmd.Process.Pid) + "\n"
	if _, err := unix.Write(reportFd, []byte(report)); err != nil {
		// runc now has no pid for this process, so nothing will ever signal,
		// count or reap it. Take it down rather than leak a container process
		// that no one can account for.
		_ = cmd.Process.Kill()
		return fmt.Errorf("report pid %d: %w", cmd.Process.Pid, err)
	}
	return nil
}
