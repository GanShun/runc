//go:build linux && cgo && seccomp

package seccomp

import (
	"fmt"
	"os"
	"testing"

	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/net/bpf"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// These are diagnostics, not tests: they print the two compilers' output for
// profiles the VM differential harness (libcontainer/seccomp/vmdiff) exercises,
// and they ask libseccomp which architectures it will accept. Nothing here
// installs a filter, so it is safe to run anywhere. They are skipped unless
// VMDIFF_DIAG=1, to keep the suite quiet:
//
//	VMDIFF_DIAG=1 CGO_ENABLED=1 go test -tags seccomp -run TestVMDiff -v ./libcontainer/seccomp/

func diagEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("VMDIFF_DIAG") == "" {
		t.Skip("set VMDIFF_DIAG=1 to run the vmdiff diagnostics")
	}
}

// TestVMDiffDumpPrograms prints the BPF both builds compile for profiles the
// harness exercises.
func TestVMDiffDumpPrograms(t *testing.T) {
	diagEnabled(t)
	ep := uint(1)
	eacces := uint(13)
	allowExit := func() []*configs.Syscall {
		return []*configs.Syscall{
			{Name: "exit", Action: configs.Allow},
			{Name: "exit_group", Action: configs.Allow},
		}
	}

	profiles := []struct {
		name string
		cfg  *configs.Seccomp
	}{
		{
			// libseccomp rewrites socket(2) on i386 into socketcall(2) with
			// arg0 == SYS_SOCKET; the Go build uses the flat i386 table.
			name: "arch-x86-listed",
			cfg: &configs.Seccomp{
				DefaultAction: configs.Allow,
				Architectures: []string{"x86"},
				Syscalls: []*configs.Syscall{
					{Name: "socket", Action: configs.Errno, ErrnoRet: &eacces},
				},
			},
		},
		{
			// The ALLOW rule equals the default action, so libseccomp drops it
			// and the ERRNO rule survives; the Go compiler keeps both and takes
			// the first matching one.
			name: "duplicate-rules-allow-then-errno",
			cfg: &configs.Seccomp{
				DefaultAction: configs.Allow,
				Syscalls: append([]*configs.Syscall{
					{Name: "close", Action: configs.Allow,
						Args: []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 12345}}},
					{Name: "close", Action: configs.Errno, ErrnoRet: &eacces,
						Args: []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 12345}}},
				}, allowExit()...),
			},
		},
		{
			// Two conditions on one argument: the Go compiler ANDs them, runc's
			// cgo path splits them into two rules.
			name: "arg-same-index-twice",
			cfg: &configs.Seccomp{
				DefaultAction: configs.Allow,
				Syscalls: append([]*configs.Syscall{
					{Name: "close", Action: configs.Errno, ErrnoRet: &eacces,
						Args: []*configs.Arg{
							{Index: 0, Op: configs.EqualTo, Value: 12345},
							{Index: 0, Op: configs.EqualTo, Value: 12346},
						}},
				}, allowExit()...),
			},
		},
		{
			// The profile allows clone but not clone3, and names statmount.
			// libseccomp knows clone (56) and not statmount, so its stub
			// boundary is 56; the Go table knows both, so its boundary is 457.
			name: "stub-boundary-libc-fallback",
			cfg: &configs.Seccomp{
				DefaultAction: configs.Errno,
				Syscalls: []*configs.Syscall{
					{Name: "clone", Action: configs.Allow},
					{Name: "statmount", Action: configs.Allow},
				},
			},
		},
		{
			// An argful rule whose action equals the default: libseccomp drops
			// it, the Go compiler keeps it. With the exit rules kept, the
			// libseccomp boundary is exit_group (231) and the Go one is
			// statmount (457).
			name: "redundant-argful-errno-rule",
			cfg: &configs.Seccomp{
				DefaultAction: configs.Errno,
				Syscalls: append([]*configs.Syscall{
					{Name: "statmount", Action: configs.Errno, ErrnoRet: &ep,
						Args: []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 0}}},
				}, allowExit()...),
			},
		},
	}

	for _, p := range profiles {
		ours, err := compileFilter(p.cfg)
		if err != nil {
			t.Errorf("%s: compileFilter: %v", p.name, err)
			continue
		}
		theirs, err := libseccompProgram(p.cfg)
		if err != nil {
			t.Errorf("%s: libseccomp: %v", p.name, err)
			continue
		}
		fmt.Printf("=== %s: go %d instructions, libseccomp+patch %d\n", p.name, len(ours), len(theirs))
		for i, ins := range ours {
			fmt.Printf("   go[%3d] %s\n", i, describe(ins))
		}
		for i, ins := range theirs {
			fmt.Printf("   cgo[%3d] %s\n", i, describe(ins))
		}
	}
}

// TestVMDiffArchCompat asks libseccomp which architectures it will add to an
// amd64 filter. It compiles only.
func TestVMDiffArchCompat(t *testing.T) {
	diagEnabled(t)
	names := []string{
		"amd64", "x86", "x32", "arm", "arm64",
		"mips", "mips64", "mips64n32", "mipsel", "mipsel64", "mipsel64n32",
		"ppc", "ppc64", "ppc64le", "riscv64", "s390", "s390x", "loongarch64",
	}
	ma, mi, mu := libseccomp.GetLibraryVersion()
	fmt.Printf("libseccomp %d.%d.%d\n", ma, mi, mu)
	for _, n := range names {
		cfg := &configs.Seccomp{DefaultAction: configs.Allow, Architectures: []string{n}}
		_, libErr := buildFilter(cfg)
		// compileFilter refuses the architectures libseccomp refuses (a byte
		// order that differs from the native one) and warns and skips any it has
		// no table for.
		_, goErr := compileFilter(cfg)
		fmt.Printf("arch %-14s libseccomp=%-90v go=%v\n", n, libErr, goErr)
	}
}

func describe(ins bpf.Instruction) string { return fmt.Sprintf("%v", ins) }
