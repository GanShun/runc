//go:build linux && cgo && seccomp && seccomp_diag

package seccomp

import (
	"fmt"

	"golang.org/x/net/bpf"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp/patchbpf"
)

// ProgramFor compiles a profile into the program this build would install, so a
// diagnostic can print it and compare it against the other build's. It is behind
// the seccomp_diag build tag because installing filters is what InitSeccomp is
// for; nothing in an ordinary build can reach this.
func ProgramFor(config *configs.Seccomp) ([]bpf.Instruction, error) {
	filter, err := buildFilter(config)
	if err != nil {
		return nil, err
	}
	defer filter.Release()

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

// BuildName names the compiler this binary carries, so a report can say which
// column it is.
func BuildName() string { return "libseccomp" }
