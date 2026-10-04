//go:build linux && cgo && seccomp

package seccomp

import (
	"fmt"
	"testing"

	"golang.org/x/net/bpf"

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
