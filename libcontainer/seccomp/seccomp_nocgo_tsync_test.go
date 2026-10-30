//go:build linux && !cgo

package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// A seccomp filter installed with prctl(2), or with seccomp(2) and no flags,
// covers the calling thread only. SECCOMP_FILTER_FLAG_TSYNC is what extends it
// to every other thread of the process. Both are kernel facts, and this is the
// only test that observes them: the flag-mapping test next door
// (seccomp_nocgo_flags_test.go) only pins flag bit -> SECCOMP_FILTER_FLAG_*.
//
// The cgo build does not honour the profile's tsync flag at all. runc's cgo
// path builds the filter with libseccomp, exports the BPF, and loads it through
// patchbpf, whose filterFlags never sets SECCOMP_FILTER_FLAG_TSYNC -- so the
// filterAttrTsync that libseccomp-golang sets on the context is dropped. The
// two builds therefore agree when the profile does not ask (neither syncs) and
// disagree when it does (this build syncs, the cgo build does not). This test
// pins the shipped build's half: asking is what makes a multi-threaded install
// cover every thread. The cgo half is asserted nowhere, because the divergence
// is a deliberate record rather than a contract; see the ADR and
// docs/seccomp-go-vs-libseccomp.md.

const tsyncHelperEnv = "RUNC_SECCOMP_TSYNC_TEST"

// TestTsyncHelperProcess is the child half of TestFilterSyncsOnlyWhenAsked. It
// is not a real test and does nothing unless the environment selects a mode.
func TestTsyncHelperProcess(t *testing.T) {
	mode := os.Getenv(tsyncHelperEnv)
	if mode == "" {
		return
	}
	runTsyncProbe(mode)
}

// TestFilterSyncsOnlyWhenAsked installs a real filter in a child and probes a
// second, already-running thread.
//
// The child is necessary twice over: installing a filter is irreversible for
// the process that installs it, and the probe has to be a distinct OS thread
// from the installer, which the process's own runtime owns. The child prints
// install-failed instead of the observation when it cannot install a filter, so
// on a host where prctl(PR_SET_SECCOMP) returns EPERM the test skips with a
// message rather than passing without having looked.
func TestFilterSyncsOnlyWhenAsked(t *testing.T) {
	if os.Getenv(tsyncHelperEnv) != "" {
		t.Skip("child process")
	}

	tests := []struct {
		mode      string
		wantErrno int64
		why       string
	}{
		{
			mode:      "noflag",
			wantErrno: 0,
			why:       "a filter with no flags covers the installing thread only",
		},
		{
			mode:      "tsync",
			wantErrno: int64(unix.EACCES),
			why:       "SECCOMP_FILTER_FLAG_TSYNC extends it to the other thread",
		},
	}

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestTsyncHelperProcess")
			cmd.Env = append(os.Environ(), tsyncHelperEnv+"="+tc.mode)
			out, err := cmd.CombinedOutput()
			if strings.Contains(string(out), "install-failed") {
				t.Skipf("cannot install a seccomp filter on this host: %s",
					strings.TrimSpace(string(out)))
			}
			if err != nil {
				t.Fatalf("helper exited with %v; output:\n%s", err, out)
			}
			// The installer thread is always filtered; that is how the test
			// knows the install happened at all.
			if want := fmt.Sprintf("installer-thread: %d", int64(unix.EACCES)); !strings.Contains(string(out), want) {
				t.Fatalf("expected %q in helper output, got:\n%s", want, out)
			}
			want := fmt.Sprintf("other-thread: %d", tc.wantErrno)
			if !strings.Contains(string(out), want) {
				t.Errorf("%s: expected %q in helper output, got:\n%s", tc.why, want, out)
			}
		})
	}
}

// runTsyncProbe installs the filter and reports what the other thread saw.
//
// The probe thread is started and parked *before* the filter is installed,
// because TSYNC applies to the threads that already exist; a thread created
// afterwards inherits the installing thread's filter regardless, which would
// make the no-flag case look synced. Both goroutines are locked to their own
// OS threads, and the channels order the two events.
func runTsyncProbe(mode string) {
	runtime.LockOSThread()

	ready := make(chan struct{})
	start := make(chan struct{})
	result := make(chan int64, 1)
	go func() {
		runtime.LockOSThread()
		close(ready)
		<-start
		_, _, errno := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
		result <- int64(errno)
	}()
	<-ready

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Printf("install-failed: no_new_privs: %v\n", err)
		os.Exit(2)
	}

	deny := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "getppid", Action: configs.Errno, ErrnoRet: &deny},
		},
	}
	if mode == "tsync" {
		config.Flags = []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_TSYNC")}
	}
	if _, err := InitSeccomp(config); err != nil {
		fmt.Printf("install-failed: %v\n", err)
		os.Exit(2)
	}

	close(start)
	other := <-result
	_, _, installer := unix.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	fmt.Printf("installer-thread: %d\n", installer)
	fmt.Printf("other-thread: %d\n", other)
	os.Exit(0)
}
