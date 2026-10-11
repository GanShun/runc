//go:build linux

package seccomp

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// This file pins the seven root causes in docs/seccomp-go-vs-libseccomp.md.
// Each test compiles the exact profile the document measured and asserts what
// the compiled program does, in the x/net/bpf interpreter, so a regression is
// caught without a VM. Divergences 1 and 2 are fixed and the tests assert the
// fixed behaviour; 3 to 7 are not, and those tests pin the current behaviour
// with a comment naming the divergence and what libseccomp does instead.
//
// The document is a measurement, so the profiles here are copied from it
// verbatim: a change to one of these tests means the document's numbers no
// longer describe this compiler and has to be re-measured.

// skipUnlessAmd64 skips a test whose syscall numbers are the document's. It
// measured on amd64; the same names have different numbers elsewhere, so the
// hard-coded numbers would mean different syscalls.
func skipUnlessAmd64(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("the document measured amd64; these syscall numbers are its")
	}
}

// hasGroup reports whether the program tests the syscall number nr for
// equality, which is how the tree emitter reaches a rule group. It is how a
// test can see that a rule for a syscall exists without depending on the exact
// jump distances around it.
func hasGroup(prog []bpf.Instruction, nr uint32) bool {
	for _, ins := range prog {
		if ji, ok := ins.(bpf.JumpIf); ok && ji.Val == nr &&
			(ji.Cond == bpf.JumpNotEqual || ji.Cond == bpf.JumpEqual) {
			return true
		}
	}
	return false
}

// argWordLoads counts loads of the high word of argument 0. A 32-bit
// architecture must not emit one, and a 64-bit architecture must.
func argWordLoads(prog []bpf.Instruction, off uint32) int {
	n := 0
	for _, ins := range prog {
		if la, ok := ins.(bpf.LoadAbsolute); ok && la.Off == off && la.Size == 4 {
			n++
		}
	}
	return n
}

// Divergence 1: a rule for socket on an architecture that multiplexes it must
// also block socketcall(2). Fixed: the compiler now emits a rule on the
// multiplexor with argument 0 equal to the subcall, alongside the flat number.
func TestDivergence1Socketcall(t *testing.T) {
	skipUnlessAmd64(t)
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
	validateProgram(t, prog)

	// Both rules are emitted: the multiplexor and the flat i386 number.
	if !hasGroup(prog, 102) {
		t.Errorf("no socketcall rule: the program has no group for syscall 102\n%s", renderProgram(prog))
	}
	if !hasGroup(prog, 359) {
		t.Errorf("no flat i386 socket rule: the program has no group for syscall 359\n%s", renderProgram(prog))
	}
	// x86 is a 32-bit architecture, so the subcall is compared against the
	// low word of argument 0, as libseccomp does. A high-word load here means
	// the comparison against the wrong half is back.
	if n := argWordLoads(prog, seccompDataArgs+argHighOffset()); n != 0 {
		t.Errorf("the x86 section loads the high word of argument 0 %d times; a 32-bit subcall is in the low word", n)
	}
	// x86_64 has no multiplexor, so nothing may be added there.
	if len(pseudoSyscalls["SCMP_ARCH_X86_64"]) != 0 {
		t.Errorf("the pseudo table has entries for x86_64: %v", pseudoSyscalls["SCMP_ARCH_X86_64"])
	}

	i386 := uint32(unix.AUDIT_ARCH_I386)
	amd64 := uint32(unix.AUDIT_ARCH_X86_64)

	// socketcall(SYS_SOCKET, ...) is the hole the document measured.
	if ret := run(t, config, seccompDataImage(102, i386, 1, 0)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("socketcall(SYS_SOCKET): got %#x, want EACCES", ret)
	}
	// A high half on the same argument must not evade it: a 64-bit process can
	// reach the i386 entry path with int 0x80 and a 64-bit register.
	if ret := run(t, config, seccompDataImage(102, i386, 1<<32|1, 0)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("socketcall(0x100000001): got %#x, want EACCES", ret)
	}
	// A different subcall of the multiplexor is untouched.
	if ret := run(t, config, seccompDataImage(102, i386, 2, 0)); ret != int(retAllow) {
		t.Errorf("socketcall(SYS_BIND): got %#x, want allow", ret)
	}
	// The flat i386 number is still blocked, for newer kernels.
	if ret := run(t, config, seccompDataImage(359, i386)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("i386 socket: got %#x, want EACCES", ret)
	}
	// The amd64 section is unchanged: it has no socketcall rule, so only the
	// native socket number is filtered.
	if ret := run(t, config, seccompDataImage(41, amd64)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("amd64 socket: got %#x, want EACCES", ret)
	}
	if ret := run(t, config, seccompDataImage(102, amd64)); ret != int(retAllow) {
		t.Errorf("amd64 nr 102 (not socketcall): got %#x, want allow", ret)
	}
}

// Divergence 1 also covers the System V IPC family, which is multiplexed
// through ipc(2) with subcall = (-pseudo) % 200.
func TestDivergence1IPCCall(t *testing.T) {
	eacces := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"x86"},
		Syscalls: []*configs.Syscall{
			{Name: "msgget", Action: configs.Errno, ErrnoRet: &eacces},
		},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	if !hasGroup(prog, 117) {
		t.Errorf("no ipc rule: the program has no group for syscall 117\n%s", renderProgram(prog))
	}
	if !hasGroup(prog, 399) {
		t.Errorf("no flat i386 msgget rule: the program has no group for syscall 399")
	}
	i386 := uint32(unix.AUDIT_ARCH_I386)
	if ret := run(t, config, seccompDataImage(117, i386, 13, 0)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("ipc(SYS_MSGGET): got %#x, want EACCES", ret)
	}
	if ret := run(t, config, seccompDataImage(117, i386, 1, 0)); ret != int(retAllow) {
		t.Errorf("ipc(SYS_SEMOP): got %#x, want allow", ret)
	}
	if ret := run(t, config, seccompDataImage(399, i386)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("i386 msgget: got %#x, want EACCES", ret)
	}
}

// Divergence 2: the cgo build's matchCall drops a rule whose action equals the
// profile's default action whatever its arguments; the Go compiler used to keep
// an argument-carrying one. Fixed: the redundant rule is gone, so the later
// stricter rule is not shadowed.
func TestDivergence2RedundantRuleDropped(t *testing.T) {
	eacces := uint(unix.EACCES)
	redundant := func() *configs.Seccomp {
		return &configs.Seccomp{
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{Name: "close", Action: configs.Allow, Args: []*configs.Arg{
					{Index: 0, Op: configs.EqualTo, Value: 12345},
				}},
				{Name: "close", Action: configs.Errno, ErrnoRet: &eacces, Args: []*configs.Arg{
					{Index: 0, Op: configs.EqualTo, Value: 12345},
				}},
			},
		}
	}
	withoutRedundant := func() *configs.Seccomp {
		return &configs.Seccomp{
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{Name: "close", Action: configs.Errno, ErrnoRet: &eacces, Args: []*configs.Arg{
					{Index: 0, Op: configs.EqualTo, Value: 12345},
				}},
			},
		}
	}

	prog, err := compileFilter(redundant())
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	want, err := compileFilter(withoutRedundant())
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	// The strongest pin: dropping the ALLOW rule leaves exactly the program the
	// profile without it compiles to.
	if !reflect.DeepEqual(prog, want) {
		t.Errorf("the redundant ALLOW rule changed the program:\n%s\nwant:\n%s",
			renderProgram(prog), renderProgram(want))
	}

	arch := nativeAuditArch(t)
	closeNr := syscallNumber(t, "close")
	if ret := run(t, redundant(), seccompDataImage(closeNr, arch, 12345)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("close(12345): got %#x, want EACCES; the ALLOW rule is shadowing the ERRNO", ret)
	}
	if ret := run(t, redundant(), seccompDataImage(closeNr, arch, 12344)); ret != int(retAllow) {
		t.Errorf("close(12344): got %#x, want allow", ret)
	}
}

// Divergence 3: the -ENOSYS boundary is computed from each implementation's
// name table, so a name only the Go table knows moves it. Not fixed.
func TestDivergence3EnosysBoundary(t *testing.T) {
	skipUnlessAmd64(t)
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{Name: "clone", Action: configs.Allow},
			{Name: "statmount", Action: configs.Allow},
		},
	}
	arch := nativeAuditArch(t)
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	// The Go table knows statmount (457), so the boundary is 457.
	if ret := run(t, config, seccompDataImage(456, arch)); ret != errnoAction(uint32(unix.EPERM)) {
		t.Errorf("nr 456 (below the Go boundary): got %#x, want EPERM", ret)
	}
	if ret := run(t, config, seccompDataImage(458, arch)); ret != int(retErrnoEnosys) {
		t.Errorf("nr 458 (above the Go boundary): got %#x, want ENOSYS", ret)
	}
	// clone3 is the syscall libc probes and falls back from. The document's
	// measurement: the Go build answers EPERM here, so the fallback to clone
	// does not happen; libseccomp's boundary is clone=56, so it answers ENOSYS
	// and the fallback succeeds.
	if ret := run(t, config, seccompDataImage(435, arch)); ret != errnoAction(uint32(unix.EPERM)) {
		t.Errorf("clone3: got %#x, want EPERM (Go boundary is 457)", ret)
	}
}

// Divergence 4: the Go table (from x/sys/unix) and libseccomp's table have
// different names. On this checkout the observable direction is that the Go
// build enforces rules for names libseccomp 2.5.5 does not resolve. Not fixed.
func TestDivergence4NameCoverage(t *testing.T) {
	skipUnlessAmd64(t)
	// kernNew are named by this checkout's x/sys/unix and not by libseccomp
	// 2.5.5; only the Go build enforces a rule naming one.
	kernNew := map[string]uint32{
		"statmount":        457,
		"listmount":        458,
		"lsm_list_modules": 461,
	}
	arch := nativeAuditArch(t)
	for name, nr := range kernNew {
		t.Run(name, func(t *testing.T) {
			config := &configs.Seccomp{
				DefaultAction: configs.Allow,
				Syscalls: []*configs.Syscall{
					{Name: name, Action: configs.Errno, ErrnoRet: new(uint)},
				},
			}
			prog, err := compileFilter(config)
			if err != nil {
				t.Fatalf("compileFilter: %v", err)
			}
			validateProgram(t, prog)
			if ret := run(t, config, seccompDataImage(nr, arch)); ret != errnoAction(0) {
				t.Errorf("%s (%d): got %#x, want ERRNO(0); libseccomp drops the rule and lets it run", name, nr, ret)
			}
		})
	}
	// uretprobe is in the x/sys table but the kernel does not implement it, so
	// the rule is unobservable in effect; libseccomp 2.5.5 does not know it.
	if _, ok := syscallNumbers["SCMP_ARCH_X86_64"]["uretprobe"]; !ok {
		t.Skip("this checkout's x/sys/unix has no uretprobe")
	}
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "uretprobe", Action: configs.Errno, ErrnoRet: new(uint)},
		},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	if ret := run(t, config, seccompDataImage(335, arch)); ret != errnoAction(0) {
		t.Errorf("uretprobe (335): got %#x, want ERRNO(0)", ret)
	}
}

// Divergence 5: two conditions on one argument. The Go compiler ANDs them into
// one rule, so contradictory values make a rule that cannot match; runc's cgo
// path splits them into two rules, so either value matches. Not fixed: which
// one a profile author meant is not decidable from the profile.
func TestDivergence5TwoConditionsOneArgument(t *testing.T) {
	eacces := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "close", Action: configs.Errno, ErrnoRet: &eacces, Args: []*configs.Arg{
				{Index: 0, Op: configs.EqualTo, Value: 12345},
				{Index: 0, Op: configs.EqualTo, Value: 12346},
			}},
		},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	arch := nativeAuditArch(t)
	closeNr := syscallNumber(t, "close")
	for _, v := range []uint64{12345, 12346} {
		if ret := run(t, config, seccompDataImage(closeNr, arch, v)); ret != int(retAllow) {
			t.Errorf("close(%d): got %#x, want allow; the two conditions are ANDed", v, ret)
		}
	}
}

// Divergence 6: with SCMP_ARCH_X32 listed, libseccomp filters x32 numbers
// through its x32 table; x/sys/unix has no x32 table, so the Go build refuses
// them with KILL_THREAD. Not fixed; fail-closed.
func TestDivergence6X32Refused(t *testing.T) {
	skipUnlessAmd64(t)
	eacces := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"x32"},
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Errno, ErrnoRet: &eacces},
		},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	amd64 := uint32(unix.AUDIT_ARCH_X86_64)
	read := syscallNumber(t, "read")
	// An x32 number is killed, not judged. libseccomp would answer EACCES.
	if ret := run(t, config, seccompDataImage(read|x32SyscallBit, amd64)); ret != int(retKillThread) {
		t.Errorf("x32 read: got %#x, want KILL_THREAD", ret)
	}
	// getpid has no rule, so libseccomp would answer ENOSYS from its x32 table
	// and the Go build kills it too.
	getpid := syscallNumber(t, "getpid")
	if ret := run(t, config, seccompDataImage(getpid|x32SyscallBit, amd64)); ret != int(retKillThread) {
		t.Errorf("x32 getpid: got %#x, want KILL_THREAD", ret)
	}
	// The same number without bit 30 is an ordinary x86-64 syscall and gets
	// the rule.
	if ret := run(t, config, seccompDataImage(read, amd64)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("amd64 read: got %#x, want EACCES", ret)
	}
}

// Divergence 7: libseccomp refuses to add an architecture whose byte order
// differs from the native one, so the cgo build fails to install a filter that
// lists one; the Go build warns and skips it. Not fixed: availability, not
// enforcement.
func TestDivergence7UnusableArchitectureSkipped(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Architectures: []string{"mips64n32"},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v (the Go build must install a filter here)", err)
	}
	validateProgram(t, prog)
	// There is no table, so no section was compiled for it; the native section
	// still applies.
	if _, ok := syscallNumbers["SCMP_ARCH_MIPS64N32"]; ok {
		t.Fatalf("this checkout has a mips64n32 table, so the test no longer pins the case")
	}
	arch := nativeAuditArch(t)
	if ret := run(t, config, seccompDataImage(0, arch)); ret != errnoAction(uint32(unix.EPERM)) {
		t.Errorf("native syscall under a mips64n32 listing: got %#x, want EPERM", ret)
	}
}

// renderProgram is a compact disassembly for failure messages.
func renderProgram(prog []bpf.Instruction) string {
	var b strings.Builder
	for i, ins := range prog {
		fmt.Fprintf(&b, "  %d: %v\n", i, ins)
	}
	return b.String()
}
