//go:build linux && !cgo

package libcontainer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
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
	cmd := exec.Command("/runc/self", "init")
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

	// The stage is this binary, re-executed: there is no helper to look up.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Path != self {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, self)
	}
	wantArgs := []string{self, RuncNsCommand, "/proc/42/ns/pid", "/runc/self", "runc-own-argv0", "init"}
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
	if err := startExecNsStage(argv, int(reportChild.Fd())); err != nil {
		t.Fatalf("startExecNsStage: %v", err)
	}
	_ = reportChild.Close()

	report, err := bufio.NewReader(reportParent).ReadString('\n')
	if err != nil {
		t.Fatalf("read reported pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(report))
	if err != nil || pid <= 0 {
		t.Fatalf("reported pid %q is not a pid: %v", report, err)
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
	if _, err := fmt.Fprintf(reportChild, "%d\n", target.Process.Pid); err != nil {
		t.Fatal(err)
	}
	_ = reportChild.Close()

	p := &setnsProcess{
		containerProcess: containerProcess{cmd: helper, process: &Process{}},
		pidReport:        reportParent,
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
				containerProcess: containerProcess{cmd: helper, process: &Process{}},
				pidReport:        reportParent,
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
		containerProcess: containerProcess{cmd: helper, process: &Process{}},
		pidReport:        reportParent,
	}
	if err := p.adoptRuncNsChild(); err == nil {
		t.Fatal("expected a malformed report to fail adoption")
	}
	assertProcessDies(t, target)
}
