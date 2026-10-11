//go:build linux

package seccomp

import (
	"encoding/binary"
	"runtime"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// These tests compile profiles and then actually run the resulting BPF in the
// interpreter from x/net/bpf, against a synthetic struct seccomp_data. That is
// the only way to be sure the jumps point the way they are meant to: a cBPF
// conditional compares K against A, and getting that backwards inverts a
// filter without failing to compile.

// maxBPFInsns is BPF_MAXINSNS, the kernel's limit for a classic BPF program.
const maxBPFInsns = 4096

// seccompDataImage builds the bytes the kernel would put in struct
// seccomp_data: int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6].
func seccompDataImage(nr, arch uint32, args ...uint64) []byte {
	buf := make([]byte, 16+8*seccompDataArgCount)
	binary.BigEndian.PutUint32(buf[seccompDataNr:], nr)
	binary.BigEndian.PutUint32(buf[seccompDataArch:], arch)
	for i := 0; i < seccompDataArgCount && i < len(args); i++ {
		// The kernel lays a 64-bit argument out in host byte order, and the
		// compiler therefore reads the low half at argLowOffset(). The VM
		// always loads big-endian, so writing each half big-endian at its
		// host offset makes the VM see exactly what the kernel would.
		base := seccompDataArg0Offset(i)
		binary.BigEndian.PutUint32(buf[base+int(argLowOffset()):], uint32(args[i]))
		binary.BigEndian.PutUint32(buf[base+int(argHighOffset()):], uint32(args[i]>>32))
	}
	return buf
}

func seccompDataArg0Offset(i int) int { return seccompDataArgs + seccompDataArgSize*i }

// run compiles config and runs the program against one seccomp_data image.
func run(t *testing.T, config *configs.Seccomp, data []byte) int {
	t.Helper()
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	if len(prog) > maxBPFInsns {
		t.Fatalf("compiled filter has %d instructions, over the kernel limit of %d", len(prog), maxBPFInsns)
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return ret
}

func nativeAuditArch(t *testing.T) uint32 {
	t.Helper()
	arch, err := nativeSeccompArch()
	if err != nil {
		t.Fatalf("nativeSeccompArch: %v", err)
	}
	audit, ok := auditArch[arch]
	if !ok {
		t.Fatalf("no audit arch for %q", arch)
	}
	return audit
}

// syscallNumber returns a syscall number that the tests can use, so they do
// not hardcode architecture-specific numbers.
func syscallNumber(t *testing.T, name string) uint32 {
	t.Helper()
	arch, err := nativeSeccompArch()
	if err != nil {
		t.Fatal(err)
	}
	num, ok := syscallNumbers[arch][name]
	if !ok {
		t.Fatalf("no %q in the table for %s", name, arch)
	}
	return num
}

func errnoAction(errno uint32) int {
	return int(retErrno | (errno & retDataMask))
}

func TestDefaultAction(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls:      []*configs.Syscall{},
	}
	ret := run(t, config, seccompDataImage(syscallNumber(t, "write"), nativeAuditArch(t)))
	if want := errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("unlisted syscall: got %#x, want %#x", ret, want)
	}
}

func TestAllowAndDeny(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Allow},
		},
	}
	arch := nativeAuditArch(t)

	if ret, want := run(t, config, seccompDataImage(syscallNumber(t, "read"), arch)), int(retAllow); ret != want {
		t.Errorf("read: got %#x, want %#x (allow)", ret, want)
	}
	if ret, want := run(t, config, seccompDataImage(syscallNumber(t, "write"), arch)), errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("write: got %#x, want %#x (errno)", ret, want)
	}
}

func TestErrnoRet(t *testing.T) {
	errno := uint(unix.EACCES)
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Errno, ErrnoRet: &errno},
		},
	}
	ret := run(t, config, seccompDataImage(syscallNumber(t, "read"), nativeAuditArch(t)))
	if want := errnoAction(uint32(unix.EACCES)); ret != want {
		t.Errorf("got %#x, want %#x", ret, want)
	}
}

func TestKillActions(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.KillProcess},
			{Name: "write", Action: configs.KillThread},
		},
	}
	arch := nativeAuditArch(t)
	if ret := run(t, config, seccompDataImage(syscallNumber(t, "read"), arch)); ret != int(retKillProcess) {
		t.Errorf("read: got %#x, want KILL_PROCESS %#x", ret, int(retKillProcess))
	}
	if ret := run(t, config, seccompDataImage(syscallNumber(t, "write"), arch)); ret != int(retKillThread) {
		t.Errorf("write: got %#x, want KILL_THREAD %#x", ret, int(retKillThread))
	}
	if ret := run(t, config, seccompDataImage(syscallNumber(t, "close"), arch)); ret != int(retAllow) {
		t.Errorf("close: got %#x, want ALLOW %#x", ret, int(retAllow))
	}
}

// TestArgumentComparisons is the one that pins down the jump directions: each
// case would still compile if a comparison were reversed, but the result
// would flip.
func TestArgumentComparisons(t *testing.T) {
	arch := nativeAuditArch(t)
	read := syscallNumber(t, "read")

	tests := []struct {
		name  string
		op    configs.Operator
		value uint64
		arg   uint64
		match bool
	}{
		{"eq match", configs.EqualTo, 42, 42, true},
		{"eq no match", configs.EqualTo, 42, 43, false},
		{"ne match", configs.NotEqualTo, 42, 43, true},
		{"ne no match", configs.NotEqualTo, 42, 42, false},
		{"gt match", configs.GreaterThan, 42, 43, true},
		{"gt equal is not greater", configs.GreaterThan, 42, 42, false},
		{"gt no match", configs.GreaterThan, 42, 41, false},
		{"ge match greater", configs.GreaterThanOrEqualTo, 42, 43, true},
		{"ge match equal", configs.GreaterThanOrEqualTo, 42, 42, true},
		{"ge no match", configs.GreaterThanOrEqualTo, 42, 41, false},
		{"lt match", configs.LessThan, 42, 41, true},
		{"lt equal is not less", configs.LessThan, 42, 42, false},
		{"lt no match", configs.LessThan, 42, 43, false},
		{"le match less", configs.LessThanOrEqualTo, 42, 41, true},
		{"le match equal", configs.LessThanOrEqualTo, 42, 42, true},
		{"le no match", configs.LessThanOrEqualTo, 42, 43, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &configs.Seccomp{
				DefaultAction: configs.Errno,
				// The rule matches argument 0 against tc; if it matches, the
				// syscall is allowed, otherwise it gets the default errno.
				Syscalls: []*configs.Syscall{
					{
						Name:   "read",
						Action: configs.Allow,
						Args: []*configs.Arg{
							{Index: 0, Op: tc.op, Value: tc.value},
						},
					},
				},
			}
			ret := run(t, config, seccompDataImage(read, arch, tc.arg))
			want := errnoAction(uint32(unix.EPERM))
			if tc.match {
				want = int(retAllow)
			}
			if ret != want {
				t.Errorf("Op %v %d against %d: got %#x, want %#x", tc.op, tc.value, tc.arg, ret, want)
			}
		})
	}
}

func TestMaskedEqual(t *testing.T) {
	arch := nativeAuditArch(t)
	read := syscallNumber(t, "read")
	// (arg & 0xff00) == 0x1200. The mask is Value and the value compared
	// against is ValueTwo, which is the order libseccomp's
	// SCMP_CMP_MASKED_EQ takes.
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{
				Name:   "read",
				Action: configs.Allow,
				Args: []*configs.Arg{
					{Index: 0, Op: configs.MaskEqualTo, Value: 0xff00, ValueTwo: 0x1200},
				},
			},
		},
	}
	if ret := run(t, config, seccompDataImage(read, arch, 0x1234)); ret != int(retAllow) {
		t.Errorf("masked match: got %#x, want allow %#x", ret, int(retAllow))
	}
	if ret, want := run(t, config, seccompDataImage(read, arch, 0x1334)), errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("masked no match: got %#x, want %#x", ret, want)
	}
}

// TestMaskedEqualAgainstZero covers the shape containerd's default profile uses
// to allow clone only when it creates no new namespaces:
//
//	(arg0 & CLONE_NEW*) == 0
//
// which is (arg0 & Value) == ValueTwo with ValueTwo zero. Reading the operands
// the other way round makes the rule match nothing, so clone is denied and
// every fork in the container fails with EPERM. It deserves its own test
// because a zero operand is easy to mistake for an unset field.
func TestMaskedEqualAgainstZero(t *testing.T) {
	arch := nativeAuditArch(t)
	clone := syscallNumber(t, "clone")
	namespaceFlags := uint64(unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWUSER)

	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{
				Name:   "clone",
				Action: configs.Allow,
				Args: []*configs.Arg{
					{Index: 0, Op: configs.MaskEqualTo, Value: namespaceFlags, ValueTwo: 0},
				},
			},
		},
	}

	// A plain clone with no namespace flags is what the rule is for.
	if ret := run(t, config, seccompDataImage(clone, arch, 0)); ret != int(retAllow) {
		t.Errorf("clone with no flags: got %#x, want allow %#x", ret, int(retAllow))
	}
	// Asking for a namespace is not covered, so it gets the default action.
	if ret, want := run(t, config, seccompDataImage(clone, arch, unix.CLONE_NEWPID)), errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("clone with CLONE_NEWPID: got %#x, want %#x", ret, want)
	}
	// A flag outside the mask is irrelevant -- the rule is about namespace
	// flags -- so this still matches and is allowed.
	if ret := run(t, config, seccompDataImage(clone, arch, uint64(unix.SIGCHLD))); ret != int(retAllow) {
		t.Errorf("clone with SIGCHLD only: got %#x, want allow %#x", ret, int(retAllow))
	}
	// Combining it with a namespace flag does not match.
	if ret, want := run(t, config, seccompDataImage(clone, arch, uint64(unix.SIGCHLD)|unix.CLONE_NEWPID)), errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("clone with SIGCHLD|CLONE_NEWPID: got %#x, want %#x", ret, want)
	}
}

// TestForeignArchKilled checks that a process running under an architecture
// the profile does not list is refused: interpreting 32-bit syscall numbers
// with a 64-bit table is a well known way to escape a seccomp filter.
func TestForeignArchKilled(t *testing.T) {
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls:      []*configs.Syscall{},
	}
	foreign := uint32(unix.AUDIT_ARCH_I386)
	if runtime.GOARCH == "386" {
		foreign = unix.AUDIT_ARCH_X86_64
	}
	ret := run(t, config, seccompDataImage(0, foreign))
	if ret != int(retKillThread) {
		t.Errorf("foreign arch: got %#x, want KILL_THREAD %#x", ret, int(retKillThread))
	}
}

// TestExtraArchitecture checks that a profile listing another architecture
// resolves that architecture's syscall numbers from its own table, not the
// native one.
func TestExtraArchitecture(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("test uses the amd64/x86 pair")
	}
	i386Read := syscallNumbers["SCMP_ARCH_X86"]["read"]
	amd64Read := syscallNumbers["SCMP_ARCH_X86_64"]["read"]
	if i386Read == amd64Read {
		t.Fatalf("expected i386 and amd64 read numbers to differ, both are %d", i386Read)
	}

	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Architectures: []string{"SCMP_ARCH_X86"},
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Allow},
		},
	}

	// Native amd64 read is allowed.
	if ret := run(t, config, seccompDataImage(amd64Read, unix.AUDIT_ARCH_X86_64)); ret != int(retAllow) {
		t.Errorf("amd64 read: got %#x, want allow", ret)
	}
	// The i386 read number is only allowed because SCMP_ARCH_X86 was added.
	if ret := run(t, config, seccompDataImage(i386Read, unix.AUDIT_ARCH_I386)); ret != int(retAllow) {
		t.Errorf("i386 read: got %#x, want allow", ret)
	}
}

// TestLargeProfileSize checks the compiled program stays inside the kernel's
// instruction limit for a profile as large as containerd's default.
func TestLargeProfileSize(t *testing.T) {
	config := &configs.Seccomp{DefaultAction: configs.Errno}
	names := make([]string, 0, len(syscallNumbers["SCMP_ARCH_X86_64"]))
	arch, _ := nativeSeccompArch()
	for name := range syscallNumbers[arch] {
		names = append(names, name)
	}
	for _, name := range names {
		config.Syscalls = append(config.Syscalls, &configs.Syscall{Name: name, Action: configs.Allow})
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	t.Logf("%d syscalls compiled to %d instructions", len(config.Syscalls), len(prog))
	if len(prog) > maxBPFInsns {
		t.Errorf("compiled filter has %d instructions, over the kernel limit of %d", len(prog), maxBPFInsns)
	}
	if _, err := bpf.NewVM(prog); err != nil {
		t.Errorf("the kernel's verifier would reject this program: %v", err)
	}
}

// TestEnosysStub covers the reason the stub exists: a syscall number past
// every number in the profile is answered with ENOSYS rather than the default
// action, which is what lets libc fall back from clone3 to clone.
func TestEnosysStub(t *testing.T) {
	arch := nativeAuditArch(t)
	max := syscallNumber(t, "openat")
	if max < syscallNumber(t, "stat") {
		t.Skip("this architecture numbers openat below stat")
	}

	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{
			{Name: "close", Action: configs.Allow},
			{Name: "openat", Action: configs.Allow},
		},
	}

	// In the profile: its own action.
	if ret := run(t, config, seccompDataImage(syscallNumber(t, "close"), arch)); ret != int(retAllow) {
		t.Errorf("close: got %#x, want allow", ret)
	}
	// Below the largest number in the profile but not in the profile: the stub
	// does not reach this, so the default action applies.
	if ret, want := run(t, config, seccompDataImage(syscallNumber(t, "stat"), arch)), errnoAction(uint32(unix.EPERM)); ret != want {
		t.Errorf("stat: got %#x, want %#x", ret, want)
	}
	// Past the end of the profile: ENOSYS, not the default action.
	for _, nr := range []uint32{max + 1, max + 100, 4200} {
		if ret := run(t, config, seccompDataImage(nr, arch)); ret != int(retErrnoEnosys) {
			t.Errorf("syscall %d: got %#x, want ENOSYS %#x", nr, ret, int(retErrnoEnosys))
		}
	}
}

// TestNoEnosysStubForPermissiveDefault checks the stub is left out when the
// default action is permissive, where an unknown syscall should just run.
func TestNoEnosysStubForPermissiveDefault(t *testing.T) {
	arch := nativeAuditArch(t)
	config := &configs.Seccomp{
		DefaultAction: configs.Allow,
		Syscalls: []*configs.Syscall{
			{Name: "openat", Action: configs.Errno},
		},
	}
	if ret := run(t, config, seccompDataImage(4200, arch)); ret != int(retAllow) {
		t.Errorf("got %#x, want allow: no stub should have been added", ret)
	}
	if _, err := enosysStub(config); err != nil {
		t.Fatalf("enosysStub: %v", err)
	} else if stub, _ := enosysStub(config); len(stub) != 0 {
		t.Errorf("stub is %d instructions, want none", len(stub))
	}
}

// TestContainerdDefaultArchitectures compiles the architecture list that
// containerd's default profile carries, which is what a Kubernetes pod gets
// from RuntimeDefault. X32 shares its AUDIT_ARCH with x86_64 and x/sys/unix
// has no x32 table, so this is where a missing table would break every real
// pod rather than some edge case.
func TestContainerdDefaultArchitectures(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("this is the amd64 architecture list")
	}
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		// The short names, because that is what specconv puts in
		// configs.Seccomp.Architectures: it converts OCI's SCMP_ARCH_* to
		// these. TestExtraArchitecture covers the other spelling.
		Architectures: []string{"amd64", "x86", "x32"},
		Syscalls: []*configs.Syscall{
			{Name: "read", Action: configs.Allow},
			{Name: "close", Action: configs.Allow},
		},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}
	if _, err := bpf.NewVM(prog); err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// The native section still has to allow what the profile allows.
	if ret := run(t, config, seccompDataImage(syscallNumber(t, "read"), nativeAuditArch(t))); ret != int(retAllow) {
		t.Errorf("native read: got %#x, want allow", ret)
	}
	// And the 32-bit section has to use the i386 numbering.
	i386Read := syscallNumbers["SCMP_ARCH_X86"]["read"]
	if ret := run(t, config, seccompDataImage(i386Read, unix.AUDIT_ARCH_I386)); ret != int(retAllow) {
		t.Errorf("i386 read: got %#x, want allow", ret)
	}
}
