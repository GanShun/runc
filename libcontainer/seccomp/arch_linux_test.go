//go:build linux

package seccomp

import "testing"

// TestSeccompArchesCoverSyscallTables pins the single architecture table against
// the generated syscall tables.
//
// The generated syscallNumbers tables are keyed by the SCMP_ARCH_* names that
// internal/mksyscalls covers. seccompArches is the source of the goarch -> SCMP
// mapping the native architecture is resolved from, now that the generated
// goarchToSeccompArch no longer exists. If an architecture is added to one side
// without the other, a native build resolves an architecture whose table does
// not exist (or a table nothing can reach), and the filter is wrong. The two
// key sets have to be the same.
func TestSeccompArchesCoverSyscallTables(t *testing.T) {
	for name, a := range seccompArches {
		if a.goarch == "" {
			continue
		}
		if _, ok := syscallNumbers[name]; !ok {
			t.Errorf("seccompArches[%q] has goarch %q but the generated tables have no entry for it", name, a.goarch)
		}
	}
	for name := range syscallNumbers {
		a, ok := seccompArches[name]
		if !ok {
			t.Errorf("the generated tables cover %q, which seccompArches does not", name)
			continue
		}
		if a.goarch == "" {
			t.Errorf("the generated tables cover %q but seccompArches gives it no goarch", name)
		}
	}
}
