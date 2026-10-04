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

// This file holds the tests that do not trust the rest of the test suite: an
// independent model of what a profile means, compared against the compiled
// program over a grid of inputs, and a static check that the program is one the
// kernel would accept.
//
// Both bugs found so far in the compiler (the architecture names, and the
// operand order of SCMP_CMP_MASKED_EQ) were invisible to hand-written tests,
// because those tests encoded the same assumption the compiler did. A model
// written from the profile semantics rather than from the generated program is
// what stops that happening again, and static validation is what the upcoming
// binary-search-tree rewrite needs in order not to quietly emit a program the
// verifier rejects.

// modelAction evaluates one syscall against a profile the way the kernel should,
// without reference to the compiled program.
func modelAction(config *configs.Seccomp, audit uint32, nr uint32, args [seccompDataArgCount]uint64) (uint32, error) {
	defaultRet, err := seccompRetAction(config.DefaultAction, config.DefaultErrnoRet)
	if err != nil {
		return 0, err
	}

	table := modelArchTable(config, audit)
	if table == nil {
		// No section covers this architecture, so the filter's
		// bad-architecture action applies.
		return retKillProcess, nil
	}

	// The -ENOSYS stub, when the profile is restrictive: a syscall number past
	// everything the profile mentions is answered with ENOSYS. Stated here
	// from the profile rather than by asking enosysStub, so that the two can
	// disagree.
	if modelStubApplies(config) {
		var max uint32
		for _, rule := range config.Syscalls {
			if rule == nil {
				continue
			}
			if num, ok := table[rule.Name]; ok && num > max {
				max = num
			}
		}
		if max != 0 && nr > max {
			return retErrnoEnosys, nil
		}
	}

	for _, rule := range config.Syscalls {
		if rule == nil {
			return 0, errBadTestProfile
		}
		want, ok := table[rule.Name]
		if !ok || want != nr {
			continue
		}
		if modelArgsMatch(rule.Args, args) {
			return seccompRetAction(rule.Action, rule.ErrnoRet)
		}
	}
	return defaultRet, nil
}

// modelSyscallNumber is the model's own lookup, which deliberately does not go
// through normalizeArch or the compiler's helpers.
func modelSyscallNumber(arch, name string) (uint32, bool) {
	table, ok := syscallNumbers[arch]
	if !ok {
		return 0, false
	}
	num, ok := table[name]
	return num, ok
}

// modelArchTable picks the architecture section an AUDIT_ARCH value lands in,
// following the documented rule: the native architecture first, then the
// profile's list, and the first architecture claiming an AUDIT_ARCH value wins.
// Names are taken in the short spelling runc's config uses.
func modelArchTable(config *configs.Seccomp, audit uint32) map[string]uint32 {
	short, err := shortNativeArch()
	if err != nil {
		return nil
	}
	seen := map[uint32]bool{}
	for _, name := range append([]string{short}, shortArchList(config.Architectures)...) {
		scmp, ok := scmpArchForShort(name)
		if !ok {
			return nil
		}
		a := auditArch[scmp]
		if seen[a] {
			continue
		}
		seen[a] = true
		table, ok := syscallNumbers[scmp]
		if !ok {
			// No table: the compiler leaves this architecture out of the
			// dispatch entirely.
			continue
		}
		if a == audit {
			return table
		}
	}
	return nil
}

// modelStubApplies restates generatePatch's two conditions.
func modelStubApplies(config *configs.Seccomp) bool {
	if config.DefaultErrnoRet != nil && uint32(*config.DefaultErrnoRet)&retDataMask == retErrnoEnosys&retDataMask {
		return false
	}
	switch config.DefaultAction {
	case configs.Allow, configs.Log, configs.Trace:
		return false
	}
	return true
}

// modelArgsMatch compares only the low 32 bits, as the kernel does.
func modelArgsMatch(args []*configs.Arg, values [seccompDataArgCount]uint64) bool {
	for _, arg := range args {
		if arg == nil || arg.Index >= seccompDataArgCount {
			return false
		}
		got := uint32(values[arg.Index])
		val := uint32(arg.Value)
		valTwo := uint32(arg.ValueTwo)
		var ok bool
		switch arg.Op {
		case configs.EqualTo:
			ok = got == val
		case configs.NotEqualTo:
			ok = got != val
		case configs.GreaterThan:
			ok = got > val
		case configs.GreaterThanOrEqualTo:
			ok = got >= val
		case configs.LessThan:
			ok = got < val
		case configs.LessThanOrEqualTo:
			ok = got <= val
		case configs.MaskEqualTo:
			// Mask first, then the value to compare against.
			ok = got&val == valTwo
		}
		if !ok {
			return false
		}
	}
	return true
}

var errBadTestProfile = errorString("test profile has a nil syscall")

type errorString string

func (e errorString) Error() string { return string(e) }

// shortNativeArch is the native architecture in the short spelling that
// configs.Seccomp uses.
func shortNativeArch() (string, error) {
	scmp, err := nativeSeccompArch()
	if err != nil {
		return "", err
	}
	short, ok := archs[scmp]
	if !ok {
		return "", errBadTestProfile
	}
	return short, nil
}

// shortArchList maps a mixed list of architecture spellings to short names.
func shortArchList(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if short, ok := archs[name]; ok {
			out = append(out, short)
			continue
		}
		out = append(out, name)
	}
	return out
}

// scmpArchForShort maps a short architecture name back to its SCMP_ARCH_* name,
// accepting either spelling.
func scmpArchForShort(name string) (string, bool) {
	if _, ok := auditArch[name]; ok {
		return name, true
	}
	for scmp, short := range archs {
		if short == name {
			return scmp, true
		}
	}
	return "", false
}

// modelProfiles is the set of profiles every structural test runs over.
func modelProfiles(t *testing.T) map[string]*configs.Seccomp {
	t.Helper()
	errno := uint(unix.ENOSYS)
	return map[string]*configs.Seccomp{
		"errno-default-only": {
			DefaultAction: configs.Errno,
		},
		"allow-list": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Allow},
				{Name: "write", Action: configs.Allow},
				{Name: "close", Action: configs.Allow},
				{Name: "openat", Action: configs.Allow},
			},
		},
		"permissive-default": {
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Errno},
				{Name: "write", Action: configs.KillProcess},
			},
		},
		"distinct-errnos": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Errno, ErrnoRet: &errno},
				{Name: "close", Action: configs.Errno, ErrnoRet: new(uint)},
			},
		},
		"every-action": {
			DefaultAction: configs.Allow,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Kill},
				{Name: "write", Action: configs.KillProcess},
				{Name: "close", Action: configs.Trap},
				{Name: "openat", Action: configs.Log},
				{Name: "stat", Action: configs.Trace},
				{Name: "fstat", Action: configs.Notify},
			},
		},
		"argument-operators": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 42}}},
				{Name: "write", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.NotEqualTo, Value: 42}}},
				{Name: "close", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.GreaterThan, Value: 42}}},
				{Name: "openat", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.GreaterThanOrEqualTo, Value: 42}}},
				{Name: "stat", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.LessThan, Value: 42}}},
				{Name: "fstat", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.LessThanOrEqualTo, Value: 42}}},
				{Name: "lseek", Action: configs.Allow, Args: []*configs.Arg{{Index: 1, Op: configs.EqualTo, Value: 7}}},
			},
		},
		"masked-equal": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				// The shape containerd's default profile uses for clone.
				{
					Name:   "clone",
					Action: configs.Allow,
					Args: []*configs.Arg{{
						Index:    0,
						Op:       configs.MaskEqualTo,
						Value:    uint64(unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWUSER),
						ValueTwo: 0,
					}},
				},
				{
					Name:   "read",
					Action: configs.Allow,
					Args: []*configs.Arg{{
						Index:    0,
						Op:       configs.MaskEqualTo,
						Value:    0xff00,
						ValueTwo: 0x1200,
					}},
				},
			},
		},
		"two-conditions": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{
					Name:   "read",
					Action: configs.Allow,
					Args: []*configs.Arg{
						{Index: 0, Op: configs.EqualTo, Value: 1},
						{Index: 1, Op: configs.GreaterThan, Value: 5},
					},
				},
			},
		},
		"extra-architectures": {
			DefaultAction: configs.Errno,
			Architectures: []string{"x86", "x32"},
			Syscalls:      []*configs.Syscall{{Name: "read", Action: configs.Allow}, {Name: "close", Action: configs.Allow}},
		},
		"duplicate-syscall": {
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Allow, Args: []*configs.Arg{{Index: 0, Op: configs.EqualTo, Value: 9}}},
				{Name: "read", Action: configs.Errno},
			},
		},
		"containerd-shaped": {
			DefaultAction: configs.Errno,
			Architectures: []string{"amd64", "x86", "x32"},
			Syscalls: []*configs.Syscall{
				{Name: "read", Action: configs.Allow},
				{Name: "write", Action: configs.Allow},
				{Name: "close", Action: configs.Allow},
				{Name: "openat", Action: configs.Allow},
				{Name: "clone", Action: configs.Allow, Args: []*configs.Arg{{
					Index:    0,
					Op:       configs.MaskEqualTo,
					Value:    uint64(unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWUSER | unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP),
					ValueTwo: 0,
				}}},
				{Name: "clone3", Action: configs.Errno, ErrnoRet: &errno},
			},
		},
	}
}

// TestAgainstModel compiles every profile and compares the program's behaviour
// with the model's over a grid of architectures, syscall numbers and argument
// values.
func TestAgainstModel(t *testing.T) {
	for name, config := range modelProfiles(t) {
		t.Run(name, func(t *testing.T) {
			prog, err := compileFilter(config)
			if err != nil {
				t.Fatalf("compileFilter: %v", err)
			}
			validateProgram(t, prog)

			audits := auditArchesToTry(t, config)
			numbers := syscallNumbersToTry(config, audits)
			argSets := argSetsToTry(config)

			cases := 0
			for _, audit := range audits {
				for _, nr := range numbers {
					for _, args := range argSets {
						want, err := modelAction(config, audit, nr, args)
						if err != nil {
							t.Fatalf("modelAction: %v", err)
						}
						vm, err := bpf.NewVM(prog)
						if err != nil {
							t.Fatalf("NewVM: %v", err)
						}
						got, err := vm.Run(seccompDataImage(nr, audit, args[:]...))
						if err != nil {
							t.Fatalf("Run(nr=%d arch=%#x args=%v): %v", nr, audit, args, err)
						}
						if uint32(got) != want {
							t.Errorf("nr=%d arch=%#x args=%v: filter said %#x, model says %#x", nr, audit, args, uint32(got), want)
						}
						cases++
					}
				}
			}
			t.Logf("%d cases over %d architectures", cases, len(audits))
		})
	}
}

// auditArchesToTry returns the architectures to feed the filter: the native one,
// any the profile adds, and one it does not mention, so the bad-architecture
// path is covered.
func auditArchesToTry(t *testing.T, config *configs.Seccomp) []uint32 {
	t.Helper()
	short, err := shortNativeArch()
	if err != nil {
		t.Fatal(err)
	}
	names := append([]string{short}, shortArchList(config.Architectures)...)

	seen := map[uint32]bool{}
	var out []uint32
	for _, name := range names {
		scmp, ok := scmpArchForShort(name)
		if !ok {
			t.Fatalf("unknown architecture %q", name)
		}
		a := auditArch[scmp]
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	// One that nothing covers.
	for _, a := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_X86_64, unix.AUDIT_ARCH_ARM} {
		if !seen[a] {
			out = append(out, a)
			break
		}
	}
	return out
}

// syscallNumbersToTry collects the numbers worth feeding to the filter: those
// the profile mentions, either side of the largest one (where the -ENOSYS stub
// changes behaviour), and a couple of unrelated ones.
func syscallNumbersToTry(config *configs.Seccomp, audits []uint32) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	add := func(nr uint32) {
		if !seen[nr] {
			seen[nr] = true
			out = append(out, nr)
		}
	}
	var max uint32
	for _, rule := range config.Syscalls {
		if rule == nil {
			continue
		}
		for _, audit := range audits {
			table := modelArchTable(config, audit)
			if table == nil {
				continue
			}
			num, ok := table[rule.Name]
			if !ok {
				continue
			}
			add(num)
			if num > max {
				max = num
			}
		}
	}
	add(0)
	add(1)
	add(4200)
	if max > 0 {
		add(max - 1)
		add(max + 1)
		add(max + 100)
	}
	return out
}

// argSetsToTry builds a small grid of argument values, biased towards the values
// the profile's conditions mention.
func argSetsToTry(config *configs.Seccomp) [][seccompDataArgCount]uint64 {
	values := map[uint64]bool{0: true, 1: true, ^uint64(0): true}
	for _, rule := range config.Syscalls {
		if rule == nil {
			continue
		}
		for _, arg := range rule.Args {
			if arg == nil {
				continue
			}
			values[arg.Value] = true
			values[arg.ValueTwo] = true
			values[arg.Value+1] = true
			values[arg.Value-1] = true
		}
	}
	// A few values over the 32-bit boundary, because only the low half is
	// compared.
	values[1<<32] = true
	values[(1<<32)|42] = true

	sorted := make([]uint64, 0, len(values))
	for v := range values {
		sorted = append(sorted, v)
	}
	// Deterministic order.
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var out [][seccompDataArgCount]uint64
	for _, v := range sorted {
		var set [seccompDataArgCount]uint64
		set[0] = v
		out = append(out, set)
	}
	// Second-argument variations, for rules that look at arg 1.
	for _, v := range sorted {
		var set [seccompDataArgCount]uint64
		set[1] = v
		out = append(out, set)
	}
	// And both together.
	for _, v := range sorted {
		var set [seccompDataArgCount]uint64
		set[0] = v
		set[1] = v
		out = append(out, set)
	}
	return out
}

// validateProgram checks the properties the kernel's verifier checks for a
// classic BPF program: every jump lands inside the program, and no reachable
// path runs off the end. The jumps in the architecture dispatch and the -ENOSYS
// stub are computed by hand, and the binary-search rewrite adds many more.
func validateProgram(t *testing.T, prog []bpf.Instruction) {
	t.Helper()
	if len(prog) == 0 {
		t.Fatal("program is empty")
	}

	for i, ins := range prog {
		check := func(skip int) {
			if target := i + 1 + skip; target >= len(prog) {
				t.Errorf("instruction %d (%v): jump to %d is outside the program (%d instructions)", i, ins, target, len(prog))
			} else if target < 0 {
				t.Errorf("instruction %d (%v): jump to %d is before the program", i, ins, target)
			}
		}
		switch v := ins.(type) {
		case bpf.JumpIf:
			check(int(v.SkipTrue))
			check(int(v.SkipFalse))
		case bpf.Jump:
			check(int(v.Skip))
		}
	}

	// Walk everything reachable from the entry point and make sure no path
	// falls off the end.
	seen := make([]bool, len(prog))
	stack := []int{0}
	for len(stack) > 0 {
		i := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if i < 0 || i >= len(prog) {
			t.Errorf("control reaches instruction %d, outside the program", i)
			continue
		}
		if seen[i] {
			continue
		}
		seen[i] = true

		var next []int
		switch v := prog[i].(type) {
		case bpf.RetConstant, bpf.RetA:
			// Terminates.
			continue
		case bpf.RawInstruction:
			if v.Op&0x07 == 0x06 { // BPF_RET
				continue
			}
			next = []int{i + 1}
		case bpf.Jump:
			next = []int{i + 1 + int(v.Skip)}
		case bpf.JumpIf:
			next = []int{i + 1 + int(v.SkipTrue), i + 1 + int(v.SkipFalse)}
		default:
			next = []int{i + 1}
		}
		for _, n := range next {
			if n == len(prog) {
				t.Errorf("instruction %d (%v) falls off the end of the program", i, prog[i])
				continue
			}
			stack = append(stack, n)
		}
	}
}

// TestProgramsWellFormed runs the structural checks over every profile,
// including ones large enough to push the hand-computed jumps around.
func TestProgramsWellFormed(t *testing.T) {
	profiles := modelProfiles(t)

	// A profile with every syscall this architecture knows, which is the
	// largest program the architecture dispatch and the stub will ever see, and
	// which also gives the stub the largest number of architectures to compare.
	short, err := shortNativeArch()
	if err != nil {
		t.Fatal(err)
	}
	table := syscallNumbers[archs0(short)]
	big := &configs.Seccomp{DefaultAction: configs.Errno}
	for name := range table {
		big.Syscalls = append(big.Syscalls, &configs.Syscall{Name: name, Action: configs.Allow})
	}
	profiles["every-syscall"] = big

	for name, config := range profiles {
		t.Run(name, func(t *testing.T) {
			prog, err := compileFilter(config)
			if err != nil {
				t.Fatalf("compileFilter: %v", err)
			}
			validateProgram(t, prog)
			if len(prog) > maxBPFInsns {
				t.Errorf("compiled to %d instructions, over the kernel limit of %d", len(prog), maxBPFInsns)
			}
		})
	}
}

// archs0 is a typo guard: it returns the SCMP_ARCH_* name for a short name.
func archs0(short string) string {
	for scmp, s := range archs {
		if s == short {
			return scmp
		}
	}
	return short
}

// TestEndiannessOfArgumentOffsets pins the offset the compiler reads an argument
// from. The other tests cannot catch a mistake here, because the helper that
// builds their seccomp_data images calls the same function the compiler does, so
// both would be wrong together. The expectation is derived from the standard
// library rather than from argLowOffset.
func TestEndiannessOfArgumentOffsets(t *testing.T) {
	var probe [2]byte
	binary.NativeEndian.PutUint16(probe[:], 0x0102)
	littleEndian := probe[0] == 0x02

	for index := 0; index < seccompDataArgCount; index++ {
		want := uint32(16 + 8*index)
		if !littleEndian {
			// On a big-endian host the low half of the argument comes second.
			want += 4
		}
		config := &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{{
				Name:   "read",
				Action: configs.Allow,
				Args:   []*configs.Arg{{Index: uint(index), Op: configs.EqualTo, Value: 1}},
			}},
		}
		prog, err := compileFilter(config)
		if err != nil {
			t.Fatalf("compileFilter: %v", err)
		}
		var found bool
		for _, ins := range prog {
			if load, ok := ins.(bpf.LoadAbsolute); ok && load.Off == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("argument %d: no load from offset %d in the compiled program", index, want)
		}
	}
}

// TestMaskedEqualOperandOrderShape checks the emitted instructions, not just the
// behaviour, because the behaviour tests were written with the operands the same
// way round as the compiler was.
func TestMaskedEqualOperandOrderShape(t *testing.T) {
	const (
		mask  = 0xff00
		value = 0x1200
	)
	config := &configs.Seccomp{
		DefaultAction: configs.Errno,
		Syscalls: []*configs.Syscall{{
			Name:   "read",
			Action: configs.Allow,
			Args:   []*configs.Arg{{Index: 0, Op: configs.MaskEqualTo, Value: mask, ValueTwo: value}},
		}},
	}
	prog, err := compileFilter(config)
	if err != nil {
		t.Fatalf("compileFilter: %v", err)
	}

	var anded, compared bool
	for _, ins := range prog {
		switch v := ins.(type) {
		case bpf.ALUOpConstant:
			if v.Op == bpf.ALUOpAnd && v.Val == mask {
				anded = true
			}
		case bpf.JumpIf:
			if v.Val == value {
				compared = true
			}
			if v.Val == mask {
				t.Error("a jump compares against the mask; the value to compare against comes second in SCMP_CMP_MASKED_EQ")
			}
		}
	}
	if !anded {
		t.Errorf("nothing masks the argument with %#x", mask)
	}
	if !compared {
		t.Errorf("nothing compares the masked argument against %#x", value)
	}
}

// TestEnosysStubOverlapCases drives generateEnosysStub directly, because the
// branches for architectures sharing an AUDIT_ARCH value (x86_64 and x32) and
// for s390's setup(2) multiplexing cannot be reached through a profile: x/sys
// has no x32 table, so no real profile produces them.
func TestEnosysStubOverlapCases(t *testing.T) {
	// One instruction the stub can jump into. Everything that reaches the
	// filter is allowed, so the test only has to distinguish ENOSYS from ALLOW.
	filter := []bpf.Instruction{bpf.RetConstant{Val: retAllow}}

	run := func(t *testing.T, stub []bpf.Instruction, nr uint32) uint32 {
		t.Helper()
		prog := append(append([]bpf.Instruction{}, stub...), filter...)
		validateProgram(t, prog)
		vm, err := bpf.NewVM(prog)
		if err != nil {
			t.Fatalf("NewVM: %v", err)
		}
		got, err := vm.Run(seccompDataImage(nr, unix.AUDIT_ARCH_X86_64))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return uint32(got)
	}

	t.Run("x86_64 and x32 share an AUDIT_ARCH", func(t *testing.T) {
		const (
			x86Max = 100
			x32Min = 0x40000000 // the x32 ABI sets bit 30
			x32Max = x32Min | 200
		)
		stub, err := generateEnosysStub(lastSyscallMap{
			unix.AUDIT_ARCH_X86_64: {
				"SCMP_ARCH_X86_64": x86Max,
				"SCMP_ARCH_X32":    x32Max,
			},
		})
		if err != nil {
			t.Fatalf("generateEnosysStub: %v", err)
		}

		// Below the x86_64 maximum: into the filter.
		if got := run(t, stub, 50); got != retAllow {
			t.Errorf("x86_64 nr 50: got %#x, want allow", got)
		}
		// Above it: ENOSYS.
		if got := run(t, stub, x86Max+1); got != retErrnoEnosys {
			t.Errorf("x86_64 nr %d: got %#x, want ENOSYS", x86Max+1, got)
		}
		// An x32 syscall below the x32 maximum is not judged by the x86_64
		// maximum, which is the whole point of the overlap case.
		if got := run(t, stub, x32Min|50); got != retAllow {
			t.Errorf("x32 nr %#x: got %#x, want allow", x32Min|50, got)
		}
		if got := run(t, stub, x32Max+1); got != retErrnoEnosys {
			t.Errorf("x32 nr %#x: got %#x, want ENOSYS", x32Max+1, got)
		}
	})

	t.Run("s390 setup multiplexing", func(t *testing.T) {
		stub, err := generateEnosysStub(lastSyscallMap{
			unix.AUDIT_ARCH_S390X: {"SCMP_ARCH_S390X": 100},
		})
		if err != nil {
			t.Fatalf("generateEnosysStub: %v", err)
		}
		prog := append(append([]bpf.Instruction{}, stub...), filter...)
		validateProgram(t, prog)
		vm, err := bpf.NewVM(prog)
		if err != nil {
			t.Fatalf("NewVM: %v", err)
		}

		// setup(2) is syscall 0, and a syscall the kernel does not know is
		// left as 0 by the multiplexing scheme, so 0 must come back ENOSYS.
		got, err := vm.Run(seccompDataImage(0, unix.AUDIT_ARCH_S390X))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if uint32(got) != retErrnoEnosys {
			t.Errorf("s390x nr 0: got %#x, want ENOSYS", uint32(got))
		}
		// And a number below the maximum still reaches the filter.
		got, err = vm.Run(seccompDataImage(50, unix.AUDIT_ARCH_S390X))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if uint32(got) != retAllow {
			t.Errorf("s390x nr 50: got %#x, want allow", uint32(got))
		}
	})
}

// TestCompileErrors covers the profiles that must be rejected rather than
// compiled into something surprising.
func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name   string
		config *configs.Seccomp
	}{
		{"nil config", nil},
		{"nil syscall", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls:      []*configs.Syscall{nil},
		}},
		{"empty syscall name", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls:      []*configs.Syscall{{Name: "", Action: configs.Allow}},
		}},
		{"invalid operator", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{{
				Name:   "read",
				Action: configs.Allow,
				Args:   []*configs.Arg{{Index: 0, Op: configs.Operator(99), Value: 1}},
			}},
		}},
		{"argument index out of range", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{{
				Name:   "read",
				Action: configs.Allow,
				Args:   []*configs.Arg{{Index: 6, Op: configs.EqualTo, Value: 1}},
			}},
		}},
		{"nil argument", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{{
				Name:   "read",
				Action: configs.Allow,
				Args:   []*configs.Arg{nil},
			}},
		}},
		{"notify on write", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls:      []*configs.Syscall{{Name: "write", Action: configs.Notify}},
		}},
		{"notify as the default action", &configs.Seccomp{
			DefaultAction: configs.Notify,
		}},
		{"unknown architecture", &configs.Seccomp{
			DefaultAction: configs.Errno,
			Architectures: []string{"SCMP_ARCH_PDP11"},
		}},
		{"unknown action", &configs.Seccomp{
			DefaultAction: configs.Action(99),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileFilter(tc.config); err == nil {
				t.Error("compileFilter accepted it, want an error")
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

// TestSyscallTableSanity checks the generated tables against numbers that can be
// read off the kernel headers, so that a broken generator cannot quietly produce
// a table that is merely self-consistent.
func TestSyscallTableSanity(t *testing.T) {
	// Name -> number, for a few syscalls whose numbering is stable and known.
	known := map[string]map[string]uint32{
		"SCMP_ARCH_X86_64":  {"read": 0, "write": 1, "open": 2, "close": 3, "clone": 56, "fork": 57, "openat": 257, "clone3": 435},
		"SCMP_ARCH_X86":     {"read": 3, "write": 4, "open": 5, "close": 6, "clone": 120, "fork": 2},
		"SCMP_ARCH_AARCH64": {"read": 63, "write": 64, "close": 57, "clone": 220, "openat": 56},
		"SCMP_ARCH_S390X":   {"read": 3, "write": 4, "close": 6, "clone": 120},
	}
	for arch, want := range known {
		table, ok := syscallNumbers[arch]
		if !ok {
			t.Errorf("%s: no table generated", arch)
			continue
		}
		for name, nr := range want {
			if got, ok := table[name]; !ok {
				t.Errorf("%s: no number for %q", arch, name)
			} else if got != nr {
				t.Errorf("%s: %q is %d, want %d", arch, name, got, nr)
			}
		}
	}

	// Every generated table should be sane: names lower-cased, numbers inside
	// the range the kernel uses.
	for arch, table := range syscallNumbers {
		if len(table) < 100 {
			t.Errorf("%s: only %d syscalls", arch, len(table))
		}
		for name, nr := range table {
			if name == "" || name != lowerASCII(name) {
				t.Errorf("%s: %q is not a lower-case syscall name", arch, name)
			}
			if nr > 0xffff {
				t.Errorf("%s: %q is %d, outside the syscall number range", arch, name, nr)
			}
		}
	}

	if runtime.GOARCH == "amd64" {
		if !binaryIsLittleEndian() {
			t.Error("amd64 is not little-endian, which would be surprising")
		}
	}
}

func lowerASCII(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + ('a' - 'A')
		}
	}
	return string(out)
}

func binaryIsLittleEndian() bool {
	var probe [2]byte
	binary.NativeEndian.PutUint16(probe[:], 0x0102)
	return probe[0] == 0x02
}
