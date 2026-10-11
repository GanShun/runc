//go:build linux && !cgo

package seccomp

import (
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// TestNocgoPseudoSyscallAssembles covers the cgo-free path specifically: the
// multiplexor rewrite is new code, and in this build the compiled program also
// goes through assembleFilterProgram, which is what the kernel is handed. The
// assembled filter is disassembled back so the rule can be checked by name
// rather than by raw opcode, and the disassembled program is then run in the
// interpreter.
func TestNocgoPseudoSyscallAssembles(t *testing.T) {
	eacces := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"x86"},
		Syscalls: []*configs.Syscall{
			{Name: "socket", Action: configs.Errno, ErrnoRet: &eacces},
		},
	}

	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	filter, err := assembleFilterProgram(prog)
	if err != nil {
		t.Fatalf("assembleFilterProgram: %v", err)
	}
	if len(filter) == 0 {
		t.Fatal("assembled filter is empty")
	}

	raw := make([]bpf.RawInstruction, len(filter))
	for i, f := range filter {
		raw[i] = bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}
	}
	assembled, all := bpf.Disassemble(raw)
	if !all {
		t.Fatalf("the assembled filter has an instruction the decoder does not know")
	}
	if !hasGroup(assembled, 102) {
		t.Errorf("assembled filter has no socketcall(102) group:\n%s", renderProgram(assembled))
	}
	if !hasGroup(assembled, 359) {
		t.Errorf("assembled filter has no flat i386 socket(359) group")
	}

	vm, err := bpf.NewVM(assembled)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	i386 := uint32(unix.AUDIT_ARCH_I386)
	ret, err := vm.Run(seccompDataImage(102, i386, 1, 0))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if uint32(ret) != uint32(errnoAction(uint32(unix.EACCES))) {
		t.Errorf("socketcall(SYS_SOCKET) on the assembled filter: got %#x, want EACCES", ret)
	}
}
