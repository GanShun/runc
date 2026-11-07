//go:build linux && !cgo

package libcontainer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests cover the wiring between runc and the RuncNsCommand staging
// stage, not the staging itself: joining a PID namespace needs a container and
// a real setns(2), so the stage is exercised only by running `runc exec`
// against one. They run only without cgo, where stageExecNs is not a no-op, and
// they need no privileges: the parts under test are the argument, descriptor
// and report-pipe conventions, which are exactly the parts a protocol change
// can silently break.

func TestSplitPidNamespacePath(t *testing.T) {
	paths := []string{
		"net:/proc/1/ns/net",
		"pid:/proc/42/ns/pid",
		"mnt:/proc/1/ns/mnt",
	}
	rest, pidPath := splitPidNamespacePath(paths)
	if pidPath != "/proc/42/ns/pid" {
		t.Fatalf("pid path = %q, want %q", pidPath, "/proc/42/ns/pid")
	}
	want := []string{"net:/proc/1/ns/net", "mnt:/proc/1/ns/mnt"}
	if !reflect.DeepEqual(rest, want) {
		t.Fatalf("rest = %v, want %v", rest, want)
	}
}

func TestSplitPidNamespacePathNoPid(t *testing.T) {
	paths := []string{"net:/proc/1/ns/net", "mnt:/proc/1/ns/mnt"}
	rest, pidPath := splitPidNamespacePath(paths)
	if pidPath != "" {
		t.Fatalf("pid path = %q, want empty", pidPath)
	}
	if !reflect.DeepEqual(rest, paths) {
		t.Fatalf("rest = %v, want %v", rest, paths)
	}
}

// TestStageExecNsWiresStage asserts the conventions the staging stage depends
// on: its argv layout, the init path handed to it, the report descriptor's
// number, and that the PID path is taken out of the list the init stage joins
// itself.
func TestStageExecNsWiresStage(t *testing.T) {
	paths := []string{"net:/proc/1/ns/net", "pid:/proc/42/ns/pid", "mnt:/proc/1/ns/mnt"}
	// The path runc built for its own child: a sealed copy of the binary. The
	// stage must be exec'd from this and not from os.Executable(), which names a
	// /memfd: while runc is running from its clone -- a path that is not on disk,
	// so the stage would fail with ENOENT.
	safeExe, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer safeExe.Close()
	// cmd.Path names safeExe by the number it gets in the child, which is what
	// container_linux.go computes.
	sealed := "/proc/self/fd/" + strconv.Itoa(stdioFdCount)
	cmd := exec.Command(sealed, "init")
	cmd.ExtraFiles = []*os.File{safeExe}
	// runc sets cmd.Args[0] to its own argv[0]; the stage has to carry it
	// through as the exec'd init's argv[0] rather than let the descriptor path
	// become the name.
	cmd.Args[0] = "runc-own-argv0"

	reportParent, reportChild, rest, err := stageExecNs(cmd, paths)
	if err != nil {
		t.Fatalf("stageExecNs: %v", err)
	}
	if reportParent == nil || reportChild == nil {
		t.Fatal("stageExecNs returned a nil report pipe")
	}
	defer reportParent.Close()
	defer reportChild.Close()

	if cmd.Path != sealed {
		t.Errorf("cmd.Path = %q, want the sealed path %q", cmd.Path, sealed)
	}
	// The report pipe is appended after safeExe, so safeExe keeps the number the
	// path names -- which is what lets the stage resolve it.
	if idx := len(cmd.ExtraFiles) - 2; cmd.ExtraFiles[idx] != safeExe {
		t.Errorf("ExtraFiles[%d] is not safeExe, so %q names the wrong descriptor", idx, cmd.Path)
	}
	// argv[0] is runc's own so an operator sees "runc runcns ..." in ps; the
	// executable is still the sealed path, and that is the assertion above.
	wantArgs := []string{"runc-own-argv0", RuncNsCommand, "/proc/42/ns/pid", sealed, "runc-own-argv0", "init"}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Errorf("cmd.Args = %v, want %v", cmd.Args, wantArgs)
	}
	wantRest := []string{"net:/proc/1/ns/net", "mnt:/proc/1/ns/mnt"}
	if !reflect.DeepEqual(rest, wantRest) {
		t.Errorf("rest = %v, want %v", rest, wantRest)
	}

	last := cmd.ExtraFiles[len(cmd.ExtraFiles)-1]
	if last != reportChild {
		t.Errorf("last ExtraFiles entry is not the report pipe's child end")
	}
	wantFd := strconv.Itoa(stdioFdCount + len(cmd.ExtraFiles) - 1)
	found := false
	for _, e := range cmd.Env {
		if e == runcNsReportFdEnv+"="+wantFd {
			found = true
		}
	}
	if !found {
		t.Errorf("cmd.Env has no %s=%s entry", runcNsReportFdEnv, wantFd)
	}
}

// puregoHelperEnv selects the child role in TestPuregoNocgoHelperProcess.
const puregoHelperEnv = "RUNC_PUREGO_TEST_ROLE"

// puregoArgvEnv names the file the "argv" role writes its own argv to.
const puregoArgvEnv = "RUNC_PUREGO_TEST_ARGV_FILE"

// TestPuregoNocgoHelperProcess is the child half of the adoption tests below.
// It is not a real test and does nothing unless the environment selects a role.
func TestPuregoNocgoHelperProcess(t *testing.T) {
	switch os.Getenv(puregoHelperEnv) {
	case "":
		return
	case "exit":
		os.Exit(0)
	case "block":
		time.Sleep(10 * time.Minute)
		os.Exit(0)
	case "argv":
		// os.Args as this process sees it: the stage passes the caller's argv0
		// as this process's argv[0], not the path it was exec'd from.
		body := strings.Join(os.Args, "\n") + "\n"
		if err := os.WriteFile(os.Getenv(puregoArgvEnv), []byte(body), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

// startPuregoHelper starts a copy of the test binary in one of the roles above.
func startPuregoHelper(t *testing.T, role string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestPuregoNocgoHelperProcess")
	cmd.Env = append(os.Environ(), puregoHelperEnv+"="+role)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper (%s): %v", role, err)
	}
	return cmd
}

// ppidOf reads the parent pid out of /proc/<pid>/status.
func ppidOf(t *testing.T, pid int) int {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("read /proc/%d/status: %v", pid, err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "PPid:"); ok {
			ppid, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return ppid
		}
	}
	t.Fatalf("/proc/%d/status has no PPid line", pid)
	return 0
}

// TestStartExecNsStageStartsCallerParentedChild runs the second half of the
// stage -- the os/exec that creates the next stage -- with no setns(2) and no
// privileges. It covers the two things a re-exec of this binary could silently
// break: the program is given the caller's argv0 rather than the path it was
// exec'd from, and the process is created as the *caller's parent's* child
// (CLONE_PARENT), which is what makes the reported pid one runc can reap.
func TestStartExecNsStageStartsCallerParentedChild(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	t.Setenv(puregoHelperEnv, "argv")
	t.Setenv(puregoArgvEnv, argvFile)

	reportParent, reportChild, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reportParent.Close()

	// argv is exactly the layout stageExecNs builds and the stage's runRuncNs
	// takes as its args[1:]: program, argv0, then the program's own arguments.
	argv := []string{os.Args[0], "runc-argv0", "-test.run=TestPuregoNocgoHelperProcess"}
	if err := startExecNsStage(argv, int(reportChild.Fd()), 0); err != nil {
		t.Fatalf("startExecNsStage: %v", err)
	}
	_ = reportChild.Close()

	report, err := bufio.NewReader(reportParent).ReadString('\n')
	if err != nil {
		t.Fatalf("read reported pid: %v", err)
	}
	pid, stageErr, err := parseRuncNsReport(report)
	if err != nil || stageErr != nil || pid <= 0 {
		t.Fatalf("report %q is not a successful report: pid %d, stage error %v, %v", report, pid, stageErr, err)
	}
	defer func() { _ = killProcess(pid) }()

	// CLONE_PARENT: the new process's parent is this process's parent, not this
	// process. It is therefore not this process's to reap, but it is the pid
	// runc ends up owning when runc is the caller.
	if want, got := os.Getppid(), ppidOf(t, pid); got != want {
		t.Errorf("child PPid = %d, want %d (the stage's own parent)", got, want)
	}

	// The stage reports the pid as soon as the process is created, so the child
	// may not have written its argv file yet.
	var body []byte
	for deadline := time.Now().Add(10 * time.Second); ; {
		body, err = os.ReadFile(argvFile)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("read the child's argv: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	want := "runc-argv0\n-test.run=TestPuregoNocgoHelperProcess\n"
	if string(body) != want {
		t.Errorf("child argv = %q, want %q", body, want)
	}
}

// assertProcessDies waits for cmd to exit after it has been killed, and fails
// if it is still running after a generous grace period.
func assertProcessDies(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_, _ = cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the process the helper created was not killed")
	}
}

// TestAdoptRuncNsChild adopts a reported pid on the normal path.
func TestAdoptRuncNsChildAdoptsReportedPid(t *testing.T) {
	helper := startPuregoHelper(t, "exit")
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	target := startPuregoHelper(t, "block")
	defer func() {
		_ = target.Process.Kill()
		_, _ = target.Process.Wait()
	}()

	reportParent, reportChild, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(reportChild, "%d ok\n", target.Process.Pid); err != nil {
		t.Fatal(err)
	}
	_ = reportChild.Close()

	p := &setnsProcess{
		containerProcess: containerProcess{cmd: helper, process: &Process{}, pidReport: reportParent},
	}
	if err := p.adoptRuncNsChild(); err != nil {
		t.Fatalf("adoptRuncNsChild: %v", err)
	}
	if p.cmd.Process.Pid != target.Process.Pid {
		t.Fatalf("adopted pid = %d, want %d", p.cmd.Process.Pid, target.Process.Pid)
	}
	if p.process.ops != p {
		t.Fatal("the adopted process did not become the Process's operations")
	}
}

// TestAdoptRuncNsChildRefusesNonPositivePid guards against a malformed report
// being read as a process group (0) or as "every process I may signal"
// (negative), which is what Kill does with a non-positive pid.
func TestAdoptRuncNsChildRefusesNonPositivePid(t *testing.T) {
	for _, pid := range []string{"0", "-1"} {
		t.Run(pid, func(t *testing.T) {
			helper := startPuregoHelper(t, "exit")
			defer func() {
				_ = helper.Process.Kill()
				_, _ = helper.Process.Wait()
			}()

			reportParent, reportChild, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(reportChild, "%s\n", pid); err != nil {
				t.Fatal(err)
			}
			_ = reportChild.Close()

			p := &setnsProcess{
				containerProcess: containerProcess{cmd: helper, process: &Process{}, pidReport: reportParent},
			}
			if err := p.adoptRuncNsChild(); err == nil {
				t.Fatalf("pid %s was accepted as a process id", pid)
			}
		})
	}
}

// TestAdoptRuncNsChildKillsUnadoptedProcess is the regression test for the leak
// in the report-error paths: the helper has already created the exec'd process,
// so a report that cannot be adopted must still take that process down.
func TestAdoptRuncNsChildKillsUnadoptedProcess(t *testing.T) {
	helper := startPuregoHelper(t, "exit")
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	target := startPuregoHelper(t, "block")
	defer func() {
		_ = target.Process.Kill()
		_, _ = target.Process.Wait()
	}()

	reportParent, reportChild, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The pid is there, as the helper would have written it, but the report is
	// not the "<pid>\n" the protocol promises. Parsing fails; the leading field
	// still names the process the helper created, and it must not survive.
	if _, err := fmt.Fprintf(reportChild, "%d not-the-protocol\n", target.Process.Pid); err != nil {
		t.Fatal(err)
	}
	_ = reportChild.Close()

	p := &setnsProcess{
		containerProcess: containerProcess{cmd: helper, process: &Process{}, pidReport: reportParent},
	}
	if err := p.adoptRuncNsChild(); err == nil {
		t.Fatal("expected a malformed report to fail adoption")
	}
	assertProcessDies(t, target)
}

// TestParseRuncNsReport pins the protocol between the stage and the runc that
// started it. Both halves are in this package, so a change that only updates one
// of them has to fail here.
func TestParseRuncNsReport(t *testing.T) {
	const tid = 4242
	for _, tc := range []struct {
		name      string
		report    string
		wantPid   int
		wantStage string
		wantErr   bool
	}{
		{
			name:    "a staged process",
			report:  "4242 ok\n",
			wantPid: tid,
		},
		{
			// The stage failed before creating anything, so there is no process
			// for runc to kill -- and the reason is still delivered, which is the
			// whole point: stderr is the container's.
			name:      "a stage that never created a process",
			report:    "0 err: open /proc/1/ns/pid: permission denied\n",
			wantStage: "open /proc/1/ns/pid: permission denied",
		},
		{
			// Created but not handed over: runc has to reap it, and the reason
			// has to survive.
			name:      "a process that could not be handed over",
			report:    "4242 err: write: broken pipe\n",
			wantPid:   tid,
			wantStage: "write: broken pipe",
		},
		{
			name:    "a report with no status",
			report:  "4242\n",
			wantErr: true,
		},
		{
			name:    "an unknown status",
			report:  "4242 maybe\n",
			wantErr: true,
		},
		{
			name:    "a report that is not a report",
			report:  "garbage\n",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid, stageErr, err := parseRuncNsReport(tc.report)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("report %q parsed as pid %d, stage error %v; want an error", tc.report, pid, stageErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRuncNsReport(%q): %v", tc.report, err)
			}
			if pid != tc.wantPid {
				t.Errorf("pid = %d, want %d", pid, tc.wantPid)
			}
			switch {
			case tc.wantStage == "" && stageErr != nil:
				t.Errorf("stage error = %v, want none", stageErr)
			case tc.wantStage != "" && stageErr == nil:
				t.Errorf("stage error = nil, want %q", tc.wantStage)
			case tc.wantStage != "" && stageErr.Error() != tc.wantStage:
				t.Errorf("stage error = %q, want %q", stageErr, tc.wantStage)
			}
		})
	}
}

// TestReportFailureUsesTheReportDescriptor is the other half of #3: a failed stage
// must tell runc why, and must not tell the container. The stage's stderr is the
// exec'd process's stderr, so a reason printed there reaches the container's log
// and leaves runc with a bare exit status.
func TestReportFailureUsesTheReportDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	t.Setenv(runcNsReportFdEnv, strconv.Itoa(int(w.Fd())))

	reportFailure(errors.New("setns(CLONE_NEWPID, /proc/1/ns/pid): permission denied"))

	_ = w.Close()
	report, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	pid, stageErr, err := parseRuncNsReport(report)
	if err != nil {
		t.Fatalf("the report the stage wrote is not one runc can read: %q: %v", report, err)
	}
	if pid != 0 {
		t.Errorf("pid = %d, want 0: no process was created, so runc must not aim at one", pid)
	}
	if stageErr == nil || !strings.Contains(stageErr.Error(), "permission denied") {
		t.Errorf("stage error = %v, want the reason to survive the round trip", stageErr)
	}
}

// TestAdoptRuncNsChildReapsAFailedHandover covers the "<pid> err:" report, which
// no stage writes today: reportFailure always reports pid 0. The branch is a guard
// on the protocol, so it is fed directly -- and it has to kill *and* reap, in that
// order. A deferred reap runs last-in-first-out and therefore before the kill, so
// a WNOHANG wait reaps nothing and the zombie the branch exists to prevent
// survives.
func TestAdoptRuncNsChildReapsAFailedHandover(t *testing.T) {
	helper := startPuregoHelper(t, "exit")
	defer func() {
		_ = helper.Process.Kill()
		_, _ = helper.Process.Wait()
	}()

	target := startPuregoHelper(t, "block")
	targetPid := target.Process.Pid

	reportParent, reportChild, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(reportChild, "%d err: could not hand over\n", targetPid); err != nil {
		t.Fatal(err)
	}
	_ = reportChild.Close()

	var seen []int
	killProcessSeen = func(pid int) { seen = append(seen, pid) }
	defer func() { killProcessSeen = nil }()

	p := &setnsProcess{
		containerProcess: containerProcess{cmd: helper, process: &Process{}, pidReport: reportParent},
	}
	if err := p.adoptRuncNsChild(); err == nil {
		t.Fatal("expected a failed handover to fail adoption")
	} else if !strings.Contains(err.Error(), "could not hand over") {
		t.Errorf("error = %v, want the stage's reason to survive", err)
	}

	// A signal to a reaped pid reaches whatever the kernel has since handed that
	// number to, so the branch has to disarm the deferred kill after waiting.
	if len(seen) != 1 || seen[0] != targetPid {
		t.Errorf("killProcess saw %v, want only the failed handover's %d", seen, targetPid)
	}

	// Killed and reaped, checked without waiting for it ourselves: kill(pid, 0)
	// on a zombie succeeds, so ESRCH is only returned once the kernel has released
	// the process. Using assertProcessDies here would hide the very thing this
	// test is for, because it reaps the zombie itself.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := unix.Kill(targetPid, 0)
		if err == unix.ESRCH {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still exists (%v) after a failed handover: killed but not reaped", targetPid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// And it must not be waiting for someone else to reap it either: ECHILD says
	// the kernel already has no child with that pid for us.
	var ws unix.WaitStatus
	if got, err := unix.Wait4(targetPid, &ws, unix.WNOHANG, nil); err != unix.ECHILD {
		t.Errorf("Wait4(%d) = %d, %v; want ECHILD: the process was left for someone else to reap", targetPid, got, err)
	}
}

// TestStageInitNsWiresStage pins what staging a container's init has to do
// differently from staging an exec, because getting any of it wrong fails
// silently rather than loudly: the clone flags would be applied to the stage
// instead of to the init, or left off the init entirely, and the container would
// come up in the wrong namespaces.
func TestStageInitNsWiresStage(t *testing.T) {
	const (
		pidPath    = "/proc/1/ns/pid"
		cloneFlags = unix.CLONE_NEWNS | unix.CLONE_NEWUTS
		pdeathsig  = unix.SIGKILL
	)
	// Built the way newParentProcess builds it: the container's namespaces are
	// already on SysProcAttr, and staging has to take them off again.
	cmd := &exec.Cmd{
		Path: "/proc/self/fd/7",
		Args: []string{"runc-own-argv0", "init"},
		Env:  []string{},
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: cloneFlags,
			Pdeathsig:  pdeathsig,
		},
	}

	reportParent, reportChild, rest, err := stageInitNs(cmd, []string{"uts:" + pidPath, "pid:" + pidPath}, cloneFlags)
	if err != nil {
		t.Fatalf("stageInitNs: %v", err)
	}
	defer reportParent.Close()
	defer reportChild.Close()

	if len(rest) != 1 || rest[0] != "uts:"+pidPath {
		t.Errorf("rest = %v, want only the uts entry: the init must not be told to join the PID path it is staged into", rest)
	}
	wantArgs := []string{"runc-own-argv0", RuncNsCommand, pidPath, "/proc/self/fd/7", "runc-own-argv0", "init"}
	if strings.Join(cmd.Args, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("args = %v, want %v", cmd.Args, wantArgs)
	}
	if cmd.Path != "/proc/self/fd/7" {
		t.Errorf("path = %q, want the sealed copy the stage and the init are both exec'd from", cmd.Path)
	}

	// The stage keeps runc's namespaces. It has to reach the PID namespace by
	// path, which it cannot do from inside a namespace it is also creating.
	if cmd.SysProcAttr.Cloneflags != 0 {
		t.Errorf("stage cloneflags = %#x, want 0: the stage is not the container", cmd.SysProcAttr.Cloneflags)
	}
	env := strings.Join(cmd.Env, "\n")
	if want := runcNsCloneFlagsEnv + "=" + strconv.FormatUint(uint64(cloneFlags), 10); !strings.Contains(env, want) {
		t.Errorf("env is missing %q, so the init's own namespaces would never be created:\n%s", want, env)
	}
	// The parent-death signal must NOT travel: CLONE_PARENT makes the child's
	// getppid() differ from this process's pid, and Go's fork code kills a child
	// whose parent-death signal cannot be armed for the right parent.
	if strings.Contains(env, "PDEATHSIG") {
		t.Errorf("the stage was told to arm a parent-death signal, which kills the child before execve:\n%s", env)
	}
	if cmd.SysProcAttr.Pdeathsig != 0 {
		t.Errorf("stage Pdeathsig = %v, want 0: checkPuregoConfig refuses the field instead", cmd.SysProcAttr.Pdeathsig)
	}

	// The report pipe is appended last so that every descriptor number computed
	// before it still names what its _LIBCONTAINER_* variable says.
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[len(cmd.ExtraFiles)-1] != reportChild {
		t.Fatalf("ExtraFiles = %v, want the report pipe's write end last", cmd.ExtraFiles)
	}
	if want := runcNsReportFdEnv + "=" + strconv.Itoa(stdioFdCount+len(cmd.ExtraFiles)-1); !strings.Contains(env, want) {
		t.Errorf("env is missing %q, so the stage would not know where to report:\n%s", want, env)
	}
}

// TestStageInitNsLeavesAnInitWithoutAPidPathAlone is the other half: with no PID
// namespace by path there is nothing to stage, and the direct child stays runc
// init -- the same rule stageExecNs follows.
func TestStageInitNsLeavesAnInitWithoutAPidPathAlone(t *testing.T) {
	cmd := &exec.Cmd{Path: "/proc/self/fd/7", Args: []string{"runc-own-argv0", "init"}, Env: []string{},
		SysProcAttr: &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}}
	paths := []string{"uts:uts"}

	reportParent, reportChild, rest, err := stageInitNs(cmd, paths, unix.CLONE_NEWNS)
	if err != nil {
		t.Fatalf("stageInitNs: %v", err)
	}
	if reportParent != nil || reportChild != nil {
		t.Error("a report pipe was created for an init that has nothing to stage")
	}
	if strings.Join(rest, ",") != strings.Join(paths, ",") {
		t.Errorf("rest = %v, want the paths unchanged", rest)
	}
	if cmd.SysProcAttr.Cloneflags != unix.CLONE_NEWNS {
		t.Errorf("stage cloneflags = %#x, want the container's %#x: nothing is staged, so the child is the init", cmd.SysProcAttr.Cloneflags, unix.CLONE_NEWNS)
	}
	if strings.Join(cmd.Args, " ") != "runc-own-argv0 init" {
		t.Errorf("args = %v, want them untouched", cmd.Args)
	}
}

// TestStagedSysProcAttrNeverArmsPdeathsig pins the invariant that cost a bug: with
// CLONE_PARENT the staged child's parent is runc, so Go's fork code -- which arms a
// requested parent-death signal by comparing the child's getppid() with the forking
// process's pid -- kills it before execve. cmd.Start() still succeeds, because a
// child that dies before execve closes the error pipe with nothing written, so the
// failure appears much later and points nowhere near the cause.
func TestStagedSysProcAttrNeverArmsPdeathsig(t *testing.T) {
	for _, cloneFlags := range []uintptr{0, unix.CLONE_NEWNS, unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP} {
		attr := stagedSysProcAttr(cloneFlags)
		if attr.Pdeathsig != 0 {
			t.Errorf("cloneFlags %#x: Pdeathsig = %v, want 0: Go would kill the child before execve", cloneFlags, attr.Pdeathsig)
		}
		if attr.Cloneflags != unix.CLONE_PARENT|cloneFlags {
			t.Errorf("cloneFlags %#x: Cloneflags = %#x, want CLONE_PARENT plus the container's namespaces", cloneFlags, attr.Cloneflags)
		}
	}
}
