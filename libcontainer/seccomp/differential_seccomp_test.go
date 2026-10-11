//go:build linux && cgo && seccomp

package seccomp

import (
	"fmt"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp/patchbpf"
)

// TestAgainstLibseccomp compares the cgo-free compiler with the filter the
// libseccomp build produces for the same profile. Both programs are run in the
// interpreter over the same inputs and their answers compared.
//
// This is the only test here that checks against something other than this
// repository's own reading of the profile semantics. The model test is written
// from the same understanding as the compiler, so a misreading shared by the two
// satisfies both -- which is how the jump-direction bug got in.
//
// It needs libseccomp and the seccomp build tag, so it lives behind
// `cgo && seccomp`. `make test` and CI pass that tag; a bare `go test ./...`
// does not, and this file then does not exist at all.
func TestAgainstLibseccomp(t *testing.T) {
	for name, config := range modelProfiles(t) {
		t.Run(name, func(t *testing.T) {
			ours, err := compileFilter(config)
			if err != nil {
				t.Fatalf("compileFilter: %v", err)
			}
			theirs, err := libseccompProgram(config)
			if err != nil {
				t.Fatalf("libseccomp: %v", err)
			}

			oursVM, err := bpf.NewVM(ours)
			if err != nil {
				t.Fatalf("NewVM(ours): %v", err)
			}
			theirsVM, err := bpf.NewVM(theirs)
			if err != nil {
				t.Fatalf("NewVM(libseccomp): %v", err)
			}

			var cases, differences int
			for _, audit := range auditArchesToTry(t, config) {
				for _, nr := range syscallNumbersToTry(config, []uint32{audit}) {
					// x32 is the one place this build cannot agree with
					// libseccomp, because x/sys/unix carries no x32 syscall
					// table. libseccomp then does one of three things and this
					// build does none of them: it kills x32 numbers when the
					// profile does not list SCMP_ARCH_X32, resolves them
					// against its x32 table when it does, and treats 0xffffffff
					// as an x32 number when the profile lists x32. Everywhere
					// else the two agree, including 0xffffffff in a profile
					// that does not mention x32. This is a deliberate gap,
					// recorded in docs/nsenter-and-runc.md.
					if profileListsX32(config) && (isX32Number(nr) || nr == ^uint32(0)) {
						continue
					}
					for _, args := range argSetsToTry(config) {
						data := seccompDataImage(nr, audit, args[:]...)

						got, err := oursVM.Run(data)
						if err != nil {
							t.Fatalf("ours: nr=%d arch=%#x: %v", nr, audit, err)
						}
						want, err := theirsVM.Run(data)
						if err != nil {
							t.Fatalf("libseccomp: nr=%d arch=%#x: %v", nr, audit, err)
						}

						cases++
						if uint32(got) != uint32(want) {
							differences++
							if differences <= 20 {
								t.Errorf("nr=%d arch=%#x args=%v: ours %#x, libseccomp %#x",
									nr, audit, args, uint32(got), uint32(want))
							}
						}
					}
				}
			}
			t.Logf("%d cases, %d differences (%d vs %d instructions)",
				cases, differences, len(ours), len(theirs))
		})
	}
}

// TestAgainstLibseccompPseudoSyscall compares the two compilers on the
// multiplexed socket and ipc syscalls, which are the divergence-1 case in
// docs/seccomp-go-vs-libseccomp.md. libseccomp rewrites a rule for `socket` on an
// architecture that multiplexes it into a rule on socketcall(2) with argument 0
// equal to SYS_SOCKET, plus the flat syscall number; the compiler has to do the
// same, and the high-bit argument sets below are what catch a comparison against
// the wrong half of the argument. The profile is not in modelProfiles because
// the model does not implement the multiplexor rewrite.
func TestAgainstLibseccompPseudoSyscall(t *testing.T) {
	eacces := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"x86"},
		Syscalls: []*configs.Syscall{
			{Name: "socket", Action: configs.Errno, ErrnoRet: &eacces},
			{Name: "msgget", Action: configs.Errno, ErrnoRet: &eacces},
			{Name: "exit", Action: configs.Allow},
			{Name: "exit_group", Action: configs.Allow},
		},
	}

	ours, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	theirs, err := libseccompProgram(config)
	if err != nil {
		t.Fatalf("libseccomp: %v", err)
	}

	oursVM, err := bpf.NewVM(ours)
	if err != nil {
		t.Fatalf("NewVM(ours): %v", err)
	}
	theirsVM, err := bpf.NewVM(theirs)
	if err != nil {
		t.Fatalf("NewVM(libseccomp): %v", err)
	}

	var cases, differences int
	// argSetsToTry is generic and does not know which argument 0 values select
	// a subcall, so add the ones that matter with high bits set: a 32-bit
	// architecture has no high word, and a comparison against the full 64-bit
	// value would wrongly fail to match these.
	argSets := argSetsToTry(config)
	for _, v := range []uint64{
		1<<32 | 1, 1<<32 | 2, 1<<32 | 13, 1<<32 | 18,
		uint64(^uint32(0))<<32 | 1,
	} {
		argSets = append(argSets, [seccompDataArgCount]uint64{v})
	}
	for _, audit := range auditArchesToTry(t, config) {
		// syscallNumbersToTry only knows the profile's flat numbers; the
		// multiplexor numbers are what this test is about, so add them.
		nums := syscallNumbersToTry(config, []uint32{audit})
		for _, name := range []string{"socket", "msgget"} {
			if ps, ok := pseudoSyscalls["SCMP_ARCH_X86"][name]; ok {
				nums = append(nums, ps.mux)
			}
		}
		for _, nr := range nums {
			for _, args := range argSets {
				data := seccompDataImage(nr, audit, args[:]...)
				got, err := oursVM.Run(data)
				if err != nil {
					t.Fatalf("ours: nr=%d arch=%#x args=%v: %v", nr, audit, args, err)
				}
				want, err := theirsVM.Run(data)
				if err != nil {
					t.Fatalf("libseccomp: nr=%d arch=%#x args=%v: %v", nr, audit, args, err)
				}
				cases++
				if uint32(got) != uint32(want) {
					differences++
					if differences <= 20 {
						t.Errorf("nr=%d arch=%#x args=%v: ours %#x, libseccomp %#x",
							nr, audit, args, uint32(got), uint32(want))
					}
				}
			}
		}
	}
	t.Logf("%d cases, %d differences (%d vs %d instructions)",
		cases, differences, len(ours), len(theirs))
}

// TestDivergence7LibseccompRefusesArch is the cgo half of the divergence-7
// pin: the Go compiler installs a filter for a profile that lists an
// architecture it has no table for, while libseccomp refuses to add the
// architecture at all. buildFilter is not exported to InitSeccomp, so this only
// compiles a filter; nothing is installed.
func TestDivergence7LibseccompRefusesArch(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"mips64n32"},
	}
	if _, err := buildFilter(config); err == nil {
		t.Errorf("libseccomp accepted mips64n32 on amd64, so the divergence is gone")
	}
	if _, err := compileFilter(config); err != nil {
		t.Errorf("the Go compiler refused mips64n32: %v", err)
	}
}

// libseccompProgram builds what runc's cgo build would install for a profile:
// libseccomp compiles it, then patchbpf prepends the -ENOSYS stub. Comparing
// against libseccomp's own output without the patch would report a difference
// for every syscall number past the end of the profile, which is the one thing
// the stub exists to change.
func libseccompProgram(config *configs.Seccomp) ([]bpf.Instruction, error) {
	filter, err := buildFilter(config)
	if err != nil {
		return nil, err
	}
	fprog, err := patchbpf.BuildProgram(config, filter)
	if err != nil {
		return nil, err
	}

	raw := make([]bpf.RawInstruction, 0, len(fprog))
	for _, ins := range fprog {
		raw = append(raw, bpf.RawInstruction{Op: ins.Code, Jt: ins.Jt, Jf: ins.Jf, K: ins.K})
	}
	prog, all := bpf.Disassemble(raw)
	if !all {
		return nil, fmt.Errorf("libseccomp produced %d instructions, at least one of which the decoder does not know", len(raw))
	}
	return prog, nil
}

// isX32Number reports whether a syscall number belongs to the x32 ABI, which
// signals itself with bit 30.
func isX32Number(nr uint32) bool {
	return nr&(1<<30) != 0 && nr != ^uint32(0)
}

// profileListsX32 reports whether a profile asks for the x32 architecture, in
// either spelling runc's config uses.
func profileListsX32(config *configs.Seccomp) bool {
	for _, arch := range config.Architectures {
		if arch == "x32" || arch == "SCMP_ARCH_X32" {
			return true
		}
	}
	return false
}
