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
// caught without a VM. All seven are now fixed, and each test asserts the
// fixed behaviour -- that the cgo-free build does what libseccomp and runc's
// cgo path do, including where that means refusing or dropping something.
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
	if len(libseccompPseudo["SCMP_ARCH_X86_64"]) != 0 {
		t.Errorf("the pseudo table has entries for x86_64: %v", libseccompPseudo["SCMP_ARCH_X86_64"])
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

// Divergence 3: the -ENOSYS boundary used to be computed from each
// implementation's own name table. Fixed: the cgo-free compiler resolves names
// through the table generated from libseccomp, so a name libseccomp cannot
// resolve does not move the boundary either.
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
	// statmount is a name libseccomp 2.5.5 does not resolve, so the rule is
	// dropped and the boundary is clone=56, exactly as the cgo build computes
	// it.
	if ret := run(t, config, seccompDataImage(55, arch)); ret != errnoAction(uint32(unix.EPERM)) {
		t.Errorf("nr 55 (below the boundary): got %#x, want EPERM", ret)
	}
	if ret := run(t, config, seccompDataImage(57, arch)); ret != int(retErrnoEnosys) {
		t.Errorf("nr 57 (above the boundary): got %#x, want ENOSYS", ret)
	}
	// clone3 is the syscall libc probes and falls back from. ENOSYS is what
	// makes the fallback to clone -- which this profile allows -- happen, and
	// it is what both builds must answer.
	if ret := run(t, config, seccompDataImage(435, arch)); ret != int(retErrnoEnosys) {
		t.Errorf("clone3: got %#x, want ENOSYS from the boundary at clone", ret)
	}
	// The dropped statmount rule does not raise the boundary either.
	if ret := run(t, config, seccompDataImage(457, arch)); ret != int(retErrnoEnosys) {
		t.Errorf("statmount: got %#x, want ENOSYS; the rule was dropped", ret)
	}
}

// Divergence 4: the Go table used to come from x/sys/unix and libseccomp's from
// its own database, so the two disagreed about names. Fixed: the generated
// table is extracted from libseccomp, so a name libseccomp cannot resolve is
// dropped by both builds and a name it resolves is enforced by both.
func TestDivergence4NameCoverage(t *testing.T) {
	skipUnlessAmd64(t)
	arch := nativeAuditArch(t)
	// Names this checkout's x/sys/unix has and libseccomp 2.5.5 does not. The
	// compiler must drop a rule naming one, because the cgo build does.
	for _, name := range []string{"statmount", "listmount", "lsm_list_modules", "uretprobe"} {
		t.Run(name, func(t *testing.T) {
			if _, ok := libseccompSyscalls["SCMP_ARCH_X86_64"][name]; ok {
				t.Fatalf("the generated table still resolves %q; regenerate it", name)
			}
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
			if ret := run(t, config, seccompDataImage(0, arch)); ret != int(retAllow) {
				t.Errorf("%s: got %#x, want allow; the rule must be dropped as libseccomp drops it", name, ret)
			}
		})
	}
	// The reverse direction: a name libseccomp resolves that the kernel-header
	// tables drop (their generator ignores numbers above 0xffff), so only the
	// libseccomp-derived table can carry it. ARM's cacheflush (0x0f0002) is the
	// case the harness cannot see.
	if nr, ok := libseccompSyscalls["SCMP_ARCH_ARM"]["cacheflush"]; !ok || nr != 0x0f0002 {
		t.Errorf("arm cacheflush in the generated table is %#x, ok=%v; want 0xf0002", nr, ok)
	}
}

// Divergence 5: two conditions on one argument. Fixed: runc's cgo path splits
// them into separate rules, because libseccomp's db_col_rule_add rejects a
// second condition on an argument index it has already seen, and the cgo-free
// compiler now splits the same way. The semantics are OR, not AND.
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
		if ret := run(t, config, seccompDataImage(closeNr, arch, v)); ret != errnoAction(uint32(unix.EACCES)) {
			t.Errorf("close(%d): got %#x, want EACCES; each condition is its own rule", v, ret)
		}
	}
	if ret := run(t, config, seccompDataImage(closeNr, arch, 12347)); ret != int(retAllow) {
		t.Errorf("close(12347): got %#x, want allow", ret)
	}
}

// Divergence 6: with SCMP_ARCH_X32 listed, libseccomp filters x32 numbers
// through its own x32 table. Fixed: the generated table carries libseccomp's
// x32 numbering, so the cgo-free compiler compiles an x32 section and
// assembleFilter dispatches to it on bit 30 of the syscall number.
func TestDivergence6X32Filtered(t *testing.T) {
	skipUnlessAmd64(t)
	eacces := uint(unix.EACCES)
	read := syscallNumber(t, "read")
	getpid := syscallNumber(t, "getpid")
	amd64 := uint32(unix.AUDIT_ARCH_X86_64)

	listed := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Architectures: []string{"x32"},
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Errno, ErrnoRet: &eacces},
		},
	}
	if nr, ok := libseccompSyscalls["SCMP_ARCH_X32"]["read"]; !ok || nr != read|x32SyscallBit {
		t.Fatalf("x32 read in the generated table is %#x, ok=%v; want %#x", nr, ok, read|x32SyscallBit)
	}
	prog, err := compileFilter(listed)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	if ret := run(t, listed, seccompDataImage(read|x32SyscallBit, amd64)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("x32 read with x32 listed: got %#x, want EACCES", ret)
	}
	// getpid does not exist on x32, so libseccomp's x32 table has no number for
	// it and the rule set has nothing to match: the default action applies and
	// the kernel answers ENOSYS on its own. Killing it, as the old compiler
	// did, is a different filter.
	if ret := run(t, listed, seccompDataImage(getpid|x32SyscallBit, amd64)); ret != int(retAllow) {
		t.Errorf("x32 getpid with x32 listed: got %#x, want allow", ret)
	}
	// An ordinary x86-64 read still gets the rule.
	if ret := run(t, listed, seccompDataImage(read, amd64)); ret != errnoAction(uint32(unix.EACCES)) {
		t.Errorf("amd64 read: got %#x, want EACCES", ret)
	}
	// Without x32 listed an x32 number is still refused, as libseccomp does.
	unlisted := &configs.Seccomp{DefaultAction: configs.Allow}
	if _, err := compileFilter(unlisted); err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	if ret := run(t, unlisted, seccompDataImage(read|x32SyscallBit, amd64)); ret != int(retKillThread) {
		t.Errorf("x32 read with x32 unlisted: got %#x, want KILL_THREAD", ret)
	}
}

// Divergence 7: libseccomp refuses to add an architecture whose byte order
// differs from the native one, so the cgo build fails to install a filter that
// lists one. Fixed: the cgo-free build refuses the same architectures, with the
// same error, rather than installing a filter the cgo build would reject.
func TestDivergence7UnusableArchitectureRefused(t *testing.T) {
	if runtime.GOARCH != "amd64" || isBigEndian {
		t.Skip("the case is a big-endian architecture added to a little-endian filter")
	}
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Architectures: []string{"mips64n32"},
	}
	_, err := compileFilter(config)
	if err == nil {
		t.Fatal("compileFilter installed a filter for a mips64n32 listing; libseccomp refuses it")
	}
	// The cgo build's message for the same condition, word for word: the cgo
	// path wraps libseccomp's EDOM text, and unix.EDOM renders as the same
	// string, so the two builds fail identically rather than merely both
	// failing.
	want := "error adding architecture to seccomp filter: numerical argument out of domain"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	// A little-endian architecture beside the native one is still added.
	config = &configs.Seccomp{
		DefaultAction: configs.Errno,
		Architectures: []string{"mipsel64n32"},
	}
	if _, err := compileFilter(config); err != nil {
		t.Errorf("compileFilter refused little-endian mipsel64n32: %v", err)
	}
}

// TestX32PairSharesOneArchiveValue pins the dispatch: two sections share the
// x86_64 audit value and are reached by testing bit 30 of the syscall number.
func TestX32PairSharesOneArchiveValue(t *testing.T) {
	skipUnlessAmd64(t)
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Architectures: []string{"x32"},
		Syscalls:      []*configs.Syscall{{Name: "read", Action: configs.Allow}},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	validateProgram(t, prog)
	if !hasGroup(prog, syscallNumber(t, "read")) {
		t.Errorf("no x86-64 read group")
	}
	x32read, ok := libseccompSyscalls["SCMP_ARCH_X32"]["read"]
	if !ok {
		t.Fatal("no x32 read in the generated table")
	}
	if !hasGroup(prog, x32read) {
		t.Errorf("no x32 read group (%#x)", x32read)
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
