//go:build linux && !cgo

package seccomp

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// TestFilterFlagsPairsTsyncEsrch pins the kernel's requirement: TSYNC and
// NEW_LISTENER both return a value, so without TSYNC_ESRCH the pair is refused
// with EINVAL and "tsync" is unusable in any profile that also says "notify".
func TestFilterFlagsPairsTsyncEsrch(t *testing.T) {
	tsync := &configs.Seccomp{
		Flags: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlag("SECCOMP_FILTER_FLAG_TSYNC")},
	}
	flags, err := filterFlags(tsync)
	if err != nil {
		t.Fatalf("filterFlags: %v", err)
	}
	if flags&unix.SECCOMP_FILTER_FLAG_TSYNC == 0 {
		t.Fatal("TSYNC is not set")
	}
	if flags&unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH == 0 {
		t.Error("TSYNC without TSYNC_ESRCH: a profile that also asks for notify cannot load")
	}

	noFlags, err := filterFlags(&configs.Seccomp{})
	if err != nil {
		t.Fatalf("filterFlags: %v", err)
	}
	if noFlags&(unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH) != 0 {
		t.Errorf("flags = %#x, want no TSYNC bits when the profile does not ask", noFlags)
	}
}

// TestSeccompFilterResult covers the success value of seccomp(2). The case that
// matters is the positive tid: the kernel reports a failed synchronisation that
// way, with errno 0, so a caller reading only errno reports success while a
// thread runs unfiltered.
func TestSeccompFilterResult(t *testing.T) {
	const tid = 12345
	for _, tc := range []struct {
		name    string
		flags   uint
		ret     uintptr
		wantFd  int
		wantErr string
	}{
		{
			name:   "listener returns the descriptor",
			flags:  unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
			ret:    7,
			wantFd: 7,
		},
		{
			name:   "sync with esrch returns zero on success",
			flags:  unix.SECCOMP_FILTER_FLAG_TSYNC | unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH,
			ret:    0,
			wantFd: -1,
		},
		{
			name:   "no flags returns zero",
			flags:  unix.SECCOMP_FILTER_FLAG_LOG,
			ret:    0,
			wantFd: -1,
		},
		{
			name:    "a positive tid is a failed sync, not success",
			flags:   unix.SECCOMP_FILTER_FLAG_TSYNC,
			ret:     tid,
			wantErr: "12345",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := seccompFilterResult(tc.flags, tc.ret)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ret %d reported success (fd %d), want an error", tc.ret, fd)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %q, want it to name the tid %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("seccompFilterResult: %v", err)
			}
			if fd != tc.wantFd {
				t.Errorf("fd = %d, want %d", fd, tc.wantFd)
			}
		})
	}
}
