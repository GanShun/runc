//go:build linux && !cgo && seccomp_diag

package seccomp

import (
	"golang.org/x/net/bpf"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// ProgramFor compiles a profile into the program this build would install, so a
// diagnostic can print it and compare it against the other build's. It is behind
// the seccomp_diag build tag because installing filters is what InitSeccomp is
// for; nothing in an ordinary build can reach this.
func ProgramFor(config *configs.Seccomp) ([]bpf.Instruction, error) {
	return compileFilter(config)
}

// BuildName names the compiler this binary carries, so a report can say which
// column it is.
func BuildName() string { return "go" }
