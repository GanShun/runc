//go:build linux && !cgo

package libcontainer

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

// These tests cover the wiring between runc and the runc-ns helper, not the
// helper itself (it lives in a separate module and is exercised end to end by
// the k4s cluster test). They run only without cgo, where stageExecNs is not a
// no-op, and they need no privileges: the parts under test are the argument,
// descriptor and report-pipe conventions, which are exactly the parts a
// protocol change can silently break.

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

// TestStageExecNsWiresHelper asserts the conventions the helper depends on: its
// argv layout, the init path handed to it, the report descriptor's number, and
// that the PID path is taken out of the list the init stage joins itself.
func TestStageExecNsWiresHelper(t *testing.T) {
	helper := filepath.Join(t.TempDir(), "runc-ns")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(runcNsHelperEnv, helper)

	paths := []string{"net:/proc/1/ns/net", "pid:/proc/42/ns/pid", "mnt:/proc/1/ns/mnt"}
	cmd := exec.Command("/runc/self", "init")
	// runc sets cmd.Args[0] to its own argv[0]; the helper has to carry it
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

	if cmd.Path != helper {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, helper)
	}
	wantArgs := []string{helper, "/proc/42/ns/pid", "/runc/self", "runc-own-argv0", "init"}
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
