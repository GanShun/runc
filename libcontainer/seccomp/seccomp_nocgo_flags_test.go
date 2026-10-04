//go:build linux && !cgo

package seccomp

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// TestFilterFlags covers the mapping from a profile's flags to the bits
// seccomp(2) takes. Nothing else exercises it: every kernel-level test installs
// a filter with no flags, so they all take the prctl(2) path and this branch is
// only reached through a profile that asks for a flag.
func TestFilterFlags(t *testing.T) {
	tests := []struct {
		name   string
		flags  []specs.LinuxSeccompFlag
		notify bool
		want   uint
	}{
		{name: "none", want: 0},
		{
			name:  "tsync",
			flags: []specs.LinuxSeccompFlag{flagTsync},
			want:  unix.SECCOMP_FILTER_FLAG_TSYNC,
		},
		{
			name:  "log",
			flags: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
			want:  unix.SECCOMP_FILTER_FLAG_LOG,
		},
		{
			name:  "spec_allow",
			flags: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagSpecAllow},
			want:  unix.SECCOMP_FILTER_FLAG_SPEC_ALLOW,
		},
		{
			name:  "wait_killable_recv",
			flags: []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagWaitKillableRecv},
			want:  unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
		},
		{
			// A rule that notifies needs a listener fd, which the kernel only
			// hands back when this flag is set.
			name:   "a notify rule asks for a listener",
			notify: true,
			want:   unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		},
		{
			name:   "several together",
			flags:  []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog, specs.LinuxSeccompFlagSpecAllow},
			notify: true,
			want: unix.SECCOMP_FILTER_FLAG_LOG |
				unix.SECCOMP_FILTER_FLAG_SPEC_ALLOW |
				unix.SECCOMP_FILTER_FLAG_NEW_LISTENER,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &configs.Seccomp{DefaultAction: configs.Allow, Flags: tc.flags}
			if tc.notify {
				config.Syscalls = []*configs.Syscall{{Name: "acct", Action: configs.Notify}}
			}
			got, err := filterFlags(config)
			if err != nil {
				t.Fatalf("filterFlags: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %#x, want %#x", got, tc.want)
			}
		})
	}
}

// TestFilterFlagsRejectsUnknown checks that a flag runc does not know is an
// error rather than being dropped, which would silently weaken the filter.
func TestFilterFlagsRejectsUnknown(t *testing.T) {
	_, err := filterFlags(&configs.Seccomp{
		DefaultAction: configs.Allow,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
	})
	var unknown *unknownFlagError
	if !errors.As(err, &unknown) {
		t.Fatalf("got %v, want an unknownFlagError", err)
	}
}

// TestFlagSupported pins what this build claims to support. The libseccomp build
// probes libseccomp and the kernel; with neither present there is nothing to
// probe, so every flag runc knows is accepted and an unusable one is rejected by
// the kernel when the filter is loaded.
func TestFlagSupported(t *testing.T) {
	for _, flag := range []specs.LinuxSeccompFlag{
		flagTsync,
		specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv,
	} {
		if err := FlagSupported(flag); err != nil {
			t.Errorf("FlagSupported(%q): %v", flag, err)
		}
	}
	if err := FlagSupported("SECCOMP_FILTER_FLAG_NOPE"); err == nil {
		t.Error("FlagSupported accepted a flag runc does not know")
	}
}
