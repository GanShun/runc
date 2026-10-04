//go:build linux && !cgo

package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// helperEnv makes the test binary re-exec itself as the process that installs
// the filter. That matters twice over: a seccomp filter cannot be removed, so
// it must not be installed in the test process, and running it under the real
// kernel is the only way to know it works. The interpreter in x/net/bpf only
// says the program means what we think it means.
const helperEnv = "RUNC_SECCOMP_TEST_SCENARIO"

// TestSeccompHelperProcess is the child half of TestInitSeccompLoads. It is not
// a real test and does nothing unless the environment selects a scenario.
func TestSeccompHelperProcess(t *testing.T) {
	scenario := os.Getenv(helperEnv)
	if scenario == "" {
		return
	}
	reportAndExit(scenario)
}

// TestInitSeccompLoads installs real filters and observes real syscalls.
func TestInitSeccompLoads(t *testing.T) {
	if os.Getenv(helperEnv) != "" {
		t.Skip("child process")
	}

	tests := []struct {
		scenario string
		want     []string
	}{
		{
			// One unconditional rule: getppid gets EACCES, and the other two
			// syscalls are untouched.
			scenario: "syscall",
			want:     []string{"fd: -1", "getppid: 13", "getpriority-arg0: 0", "getpriority-arg1: 0"},
		},
		{
			// A rule with an argument condition: only getpriority(0, _)
			// matches, getpriority(1, _) falls through to the default.
			scenario: "arg",
			want:     []string{"fd: -1", "getppid: 0", "getpriority-arg0: 13", "getpriority-arg1: 0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.scenario, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestSeccompHelperProcess")
			cmd.Env = append(os.Environ(), helperEnv+"="+tc.scenario)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helper exited with %v; output:\n%s", err, out)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(out), want) {
					t.Errorf("expected %q in helper output, got:\n%s", want, out)
				}
			}
		})
	}
}

// reportAndExit installs the scenario's filter and prints what the kernel did
// to a few syscalls, then exits without unwinding the test framework.
func reportAndExit(scenario string) {
	deny := uint(unix.EACCES)

	var config *configs.Seccomp
	switch scenario {
	case "syscall":
		config = &configs.Seccomp{
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{Name: "getppid", Action: configs.Errno, ErrnoRet: &deny},
			},
		}
	case "arg":
		config = &configs.Seccomp{
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{
					Name:     "getpriority",
					Action:   configs.Errno,
					ErrnoRet: &deny,
					Args:     []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 0}},
				},
			},
		}
	default:
		fmt.Printf("install-failed: unknown scenario %q\n", scenario)
		os.Exit(2)
	}

	// runc sets this before installing a filter (standard_init_linux.go), and
	// an unprivileged process cannot install one without it.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Printf("install-failed: no_new_privs: %v\n", err)
		os.Exit(2)
	}
	fd, err := InitSeccomp(config)
	if err != nil {
		fmt.Printf("install-failed: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("fd: %d\n", fd)

	_, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	fmt.Printf("getppid: %d\n", errno)
	// which=0 is PRIO_PROCESS, which the "arg" rule matches; which=1 is
	// PRIO_PGRP, which it does not.
	_, _, errno = unix.RawSyscall(unix.SYS_GETPRIORITY, 0, 0, 0)
	fmt.Printf("getpriority-arg0: %d\n", errno)
	_, _, errno = unix.RawSyscall(unix.SYS_GETPRIORITY, 1, 0, 0)
	fmt.Printf("getpriority-arg1: %d\n", errno)

	os.Exit(0)
}
