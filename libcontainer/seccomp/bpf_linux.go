//go:build linux

package seccomp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sort"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// This file builds a seccomp filter for the cgo-free build, where libseccomp
// is not available. libseccomp both compiles a profile into classic BPF and
// loads it; only the loading half exists in Go (see patchbpf), so this
// reimplements the compilation half.
//
// The filter it builds is a linear chain of one block per syscall:
//
//	ld  [0]            ; seccomp_data.nr
//	jne N -> skip body ; this is not the syscall we are looking at
//	<body>             ; argument tests, then ret <action>
//	...
//	ret <default>
//
// A linear chain is correct but runs in O(number of rules) per syscall, where
// libseccomp builds a binary search tree and runs in O(log n). The default
// profile has several hundred rules, so this is the main thing to improve; the
// chain is used first because every jump in it is short, which keeps the
// encoder simple, whereas a tree needs long jumps through 32-bit unconditonals.

// x32SyscallBit marks an x32 syscall. x32 is an ILP32 ABI on x86-64, signalled
// per syscall rather than per process: seccomp_data.arch is AUDIT_ARCH_X86_64
// for both ABIs, so bit 30 of the syscall number is the only way to tell them
// apart.
const x32SyscallBit = 1 << 30

// Offsets into struct seccomp_data (linux/seccomp.h).
const (
	seccompDataNr       = 0
	seccompDataArch     = 4
	seccompDataArgs     = 16
	seccompDataArgSize  = 8
	seccompDataArgCount = 6
)

// isBigEndian reports the host byte order. The kernel runs a seccomp filter
// over struct seccomp_data in host byte order -- verified against the running
// kernel, where a plain comparison against a syscall number matches -- so the
// two halves of a 64-bit argument swap places on a big-endian machine.
var isBigEndian = func() bool {
	var buf [2]byte
	binary.NativeEndian.PutUint16(buf[:], 0x0102)
	return buf[0] == 0x01
}()

// argLowOffset is the offset of the low 32 bits of an argument within its
// 8-byte slot, and argHighOffset the offset of the high 32 bits. seccomp
// compares only the low 32 bits, cBPF being unable to express the upper half.
func argLowOffset() uint32 {
	if isBigEndian {
		return 4
	}
	return 0
}

func argHighOffset() uint32 { return 4 - argLowOffset() }

// SECCOMP_RET_* actions (linux/seccomp.h). The low 16 bits carry the data
// (the errno for SECCOMP_RET_ERRNO, the ptrace event for SECCOMP_RET_TRACE).
const (
	retKillProcess = 0x80000000
	retKillThread  = 0x00000000
	retTrap        = 0x00030000
	retErrno       = 0x00050000
	retUserNotif   = 0x7fc00000
	retTrace       = 0x7ff00000
	retLog         = 0x7ffc0000
	retAllow       = 0x7fff0000
	retDataMask    = 0x0000ffff
)

// auditArch maps a seccomp architecture name (SCMP_ARCH_*) to the
// AUDIT_ARCH_* value that appears in seccomp_data.arch.
var auditArch = map[string]uint32{
	"SCMP_ARCH_X86":         unix.AUDIT_ARCH_I386,
	"SCMP_ARCH_X86_64":      unix.AUDIT_ARCH_X86_64,
	"SCMP_ARCH_X32":         unix.AUDIT_ARCH_X86_64, // x32 shares the x86_64 arch value
	"SCMP_ARCH_ARM":         unix.AUDIT_ARCH_ARM,
	"SCMP_ARCH_AARCH64":     unix.AUDIT_ARCH_AARCH64,
	"SCMP_ARCH_MIPS":        unix.AUDIT_ARCH_MIPS,
	"SCMP_ARCH_MIPS64":      unix.AUDIT_ARCH_MIPS64,
	"SCMP_ARCH_MIPS64N32":   unix.AUDIT_ARCH_MIPS64N32,
	"SCMP_ARCH_MIPSEL":      unix.AUDIT_ARCH_MIPSEL,
	"SCMP_ARCH_MIPSEL64":    unix.AUDIT_ARCH_MIPSEL64,
	"SCMP_ARCH_MIPSEL64N32": unix.AUDIT_ARCH_MIPSEL64N32,
	"SCMP_ARCH_PPC":         unix.AUDIT_ARCH_PPC,
	"SCMP_ARCH_PPC64":       unix.AUDIT_ARCH_PPC64,
	"SCMP_ARCH_PPC64LE":     unix.AUDIT_ARCH_PPC64LE,
	"SCMP_ARCH_RISCV64":     unix.AUDIT_ARCH_RISCV64,
	"SCMP_ARCH_S390":        unix.AUDIT_ARCH_S390,
	"SCMP_ARCH_S390X":       unix.AUDIT_ARCH_S390X,
	"SCMP_ARCH_LOONGARCH64": unix.AUDIT_ARCH_LOONGARCH64,
}

// archIs32Bit reports whether an architecture compares only the low 32 bits of
// a syscall argument, which is what libseccomp does when its arch definition
// has ARCH_SIZE_32. It cannot be read off the AUDIT_ARCH value: x32 shares
// x86_64's value and is 32-bit, and the two mips n32 ABIs set the 64-bit bit
// in their own. An architecture not listed is 64-bit.
var archIs32Bit = map[string]bool{
	"SCMP_ARCH_X86":         true,
	"SCMP_ARCH_X32":         true,
	"SCMP_ARCH_ARM":         true,
	"SCMP_ARCH_MIPS":        true,
	"SCMP_ARCH_MIPS64N32":   true,
	"SCMP_ARCH_MIPSEL":      true,
	"SCMP_ARCH_MIPSEL64N32": true,
	"SCMP_ARCH_PPC":         true,
	"SCMP_ARCH_S390":        true,
}

// archLittleEndian reports an architecture's byte order. libseccomp refuses to
// add an architecture whose byte order differs from the native one -- its filter
// cannot compare seccomp_data in both orders, so db_col_db_add() returns EDOM --
// and the cgo-free build refuses the same ones. An architecture not listed is
// treated as the native byte order and is never refused.
var archLittleEndian = map[string]bool{
	"SCMP_ARCH_X86":         true,
	"SCMP_ARCH_X86_64":      true,
	"SCMP_ARCH_X32":         true,
	"SCMP_ARCH_ARM":         true,
	"SCMP_ARCH_AARCH64":     true,
	"SCMP_ARCH_LOONGARCH64": true,
	"SCMP_ARCH_MIPS":        false,
	"SCMP_ARCH_MIPS64":      false,
	"SCMP_ARCH_MIPS64N32":   false,
	"SCMP_ARCH_MIPSEL":      true,
	"SCMP_ARCH_MIPSEL64":    true,
	"SCMP_ARCH_MIPSEL64N32": true,
	"SCMP_ARCH_PPC":         false,
	"SCMP_ARCH_PPC64":       false,
	"SCMP_ARCH_PPC64LE":     true,
	"SCMP_ARCH_RISCV64":     true,
	"SCMP_ARCH_S390":        false,
	"SCMP_ARCH_S390X":       false,
}

// archSyscallTables returns an architecture's syscall name -> number table and
// its multiplexor table. libseccomp's generated tables (libseccomp_linux.go) are
// authoritative wherever they exist, so the two builds resolve the same names;
// the kernel-header table (syscalls_linux.go) is the fallback for an
// architecture the libseccomp these were generated from has no table for -- on
// libseccomp 2.5.5 that is loongarch64 only.
func archSyscallTables(arch string) (map[string]uint32, map[string]pseudoSyscall, bool) {
	if table, ok := libseccompSyscalls[arch]; ok {
		return table, libseccompPseudo[arch], true
	}
	if table, ok := syscallNumbers[arch]; ok {
		return table, nil, true
	}
	return nil, nil, false
}

// seccompRetAction converts a libcontainer action into the SECCOMP_RET_* value
// to return.
func seccompRetAction(action configs.Action, errnoRet *uint) (uint32, error) {
	var ret uint32
	switch action {
	case configs.Kill, configs.KillThread:
		return retKillThread, nil
	case configs.KillProcess:
		return retKillProcess, nil
	case configs.Trap:
		return retTrap, nil
	case configs.Errno:
		ret = retErrno
	case configs.Trace:
		ret = retTrace
	case configs.Log:
		return retLog, nil
	case configs.Notify:
		return retUserNotif, nil
	case configs.Allow:
		return retAllow, nil
	default:
		return 0, fmt.Errorf("invalid action %d, cannot use in rule", action)
	}

	// Errno and Trace carry a value; both default to EPERM, matching
	// libseccomp's behaviour in the cgo build.
	errno := uint32(unix.EPERM)
	if errnoRet != nil {
		errno = uint32(*errnoRet)
	}
	return ret | (errno & retDataMask), nil
}

// nativeSeccompArch returns the seccomp architecture name for the architecture
// runc was built for.
func nativeSeccompArch() (string, error) {
	arch, ok := goarchToSeccompArch[runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("no seccomp syscall table for GOARCH %q", runtime.GOARCH)
	}
	return arch, nil
}

// archSection is one architecture's worth of compiled rules.
type archSection struct {
	auditArch uint32
	// arch is the SCMP_ARCH_* name, which is how the x32/x86_64 pair sharing
	// one AUDIT_ARCH value is told apart at dispatch time.
	arch string
	prog []bpf.Instruction
}

// normalizeArch turns an architecture name from a profile into the SCMP_ARCH_*
// name the tables are keyed by. Both spellings turn up: specconv converts OCI's
// "SCMP_ARCH_X86_64" into the short "amd64" for configs.Seccomp.Architectures,
// while the native architecture is known here by its SCMP_ARCH_* name.
func normalizeArch(name string) (string, bool) {
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

// compileFilter compiles a seccomp profile into a classic BPF program.
func compileFilter(config *configs.Seccomp) ([]bpf.Instruction, error) {
	if config == nil {
		return nil, errors.New("nil seccomp config")
	}

	defaultRet, err := seccompRetAction(config.DefaultAction, config.DefaultErrnoRet)
	if err != nil {
		return nil, fmt.Errorf("invalid default action: %w", err)
	}
	if config.DefaultAction == configs.Notify {
		// Matches the cgo build: runc has to write the seccomp fd to its
		// parent after installing the filter, and a notifying write would
		// never get there.
		return nil, errors.New("SCMP_ACT_NOTIFY cannot be used as default action")
	}

	// The native architecture is always present; config.Architectures adds
	// any others a profile wants to allow (a 32-bit process on a 64-bit
	// kernel, typically).
	native, err := nativeSeccompArch()
	if err != nil {
		return nil, err
	}
	arches := append([]string{native}, config.Architectures...)

	sections := make([]archSection, 0, len(arches))
	seen := make(map[string]bool, len(arches))

	for _, name := range arches {
		arch, ok := normalizeArch(name)
		if !ok {
			return nil, fmt.Errorf("unknown seccomp architecture %q", name)
		}
		// Each architecture token is added once; listing the native one again
		// is a no-op, as it is in libseccomp.
		if seen[arch] {
			continue
		}
		seen[arch] = true

		// libseccomp refuses (EDOM) to add an architecture whose byte order
		// differs from the native one, and the cgo build turns that into a
		// failed install. Refusing the same architectures keeps the two builds
		// equivalent: an extra section the kernel can never match is not the
		// same filter if one build installs it and the other does not.
		if little, ok := archLittleEndian[arch]; ok && little != !isBigEndian {
			return nil, fmt.Errorf("error adding architecture to seccomp filter: %w", unix.EDOM)
		}

		table, pseudo, ok := archSyscallTables(arch)
		if !ok {
			// No name table for this architecture. Leaving it out of the
			// dispatch means the filter's bad-architecture action refuses it,
			// which is fail-closed and better than filtering it with the wrong
			// numbering.
			logrus.Warnf("seccomp: no syscall table for architecture %q, refusing it rather than filtering it", name)
			continue
		}
		prog, err := compileArchSection(config, table, pseudo, defaultRet, arch)
		if err != nil {
			return nil, err
		}
		sections = append(sections, archSection{auditArch: auditArch[arch], arch: arch, prog: prog})
	}

	prog, err := assembleFilter(sections)
	if err != nil {
		return nil, err
	}

	// The stub goes in front, so that a syscall the profile knows nothing about
	// is answered with ENOSYS rather than the default action.
	stub, err := enosysStub(config)
	if err != nil {
		return nil, err
	}
	if len(stub) == 0 {
		return prog, nil
	}
	return append(stub, prog...), nil
}

// assembleFilter lays out the architecture dispatch followed by each
// architecture's section.
//
//	ld  [4]                 ; seccomp_data.arch
//	jeq A0 -> arch0
//	jeq A1 -> arch1
//	...
//	ret KILL_THREAD         ; the arch matched nothing
//	arch0:
//	  ...
//	arch1:
//	  ...
//
// Two architectures can share one AUDIT_ARCH value: x32 and x86_64 both report
// AUDIT_ARCH_X86_64, and bit 30 of the syscall number is the only signal that
// tells them apart. That pair is dispatched by testing the bit.
func assembleFilter(sections []archSection) ([]bpf.Instruction, error) {
	type group struct {
		audit uint32
		secs  []archSection
	}
	var groups []group
	index := map[uint32]int{}
	for _, s := range sections {
		at, ok := index[s.auditArch]
		if !ok {
			index[s.auditArch] = len(groups)
			groups = append(groups, group{audit: s.auditArch, secs: []archSection{s}})
			continue
		}
		groups[at].secs = append(groups[at].secs, s)
	}

	b := &builder{}
	b.emit(bpf.LoadAbsolute{Off: seccompDataArch, Size: 4})
	for i, g := range groups {
		b.jumpIf(bpf.JumpEqual, g.audit, fmt.Sprintf("arch%d", i))
	}
	// Reached only when the architecture is none of the above. libseccomp
	// returns SECCOMP_RET_KILL_THREAD here, not KILL_PROCESS, and matching it
	// matters: a thread killed by KILL_THREAD leaves the rest of a threaded
	// process running, which is not the same filter.
	b.emit(bpf.RetConstant{Val: retKillThread})

	for i, g := range groups {
		b.label(fmt.Sprintf("arch%d", i))
		if len(g.secs) == 1 {
			b.emit(g.secs[0].prog...)
			continue
		}

		var x32, x64 *archSection
		for j := range g.secs {
			if g.secs[j].arch == "SCMP_ARCH_X32" {
				x32 = &g.secs[j]
			} else {
				x64 = &g.secs[j]
			}
		}
		if x32 == nil || x64 == nil {
			return nil, fmt.Errorf("seccomp: architectures share audit value %#x but are not the x86_64/x32 pair", g.audit)
		}
		// seccomp_data.arch is AUDIT_ARCH_X86_64 for both ABIs; bit 30 of the
		// syscall number is what says which one this is.
		b.emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})
		b.jumpIf(bpf.JumpBitsSet, x32SyscallBit, fmt.Sprintf("arch%d_x32", i))
		b.jumpTo(fmt.Sprintf("arch%d_x64", i))
		b.label(fmt.Sprintf("arch%d_x32", i))
		b.emit(x32.prog...)
		b.label(fmt.Sprintf("arch%d_x64", i))
		b.emit(x64.prog...)
	}

	prog, err := b.assemble()
	if err != nil {
		return nil, fmt.Errorf("assembling seccomp filter: %w", err)
	}
	return prog, nil
}

// A classic BPF conditional jump only reaches 255 instructions ahead, and a
// profile for a restrictive default has several hundred rules, so the jumps a
// binary search tree needs cannot be worked out by hand. These are the pieces of
// a small assembler with labels: a conditional jump that cannot reach its target
// in one instruction becomes a conditional that falls through onto a 32-bit
// unconditional jump, which reaches anywhere. cBPF cannot jump backwards, so
// every target has to be ahead of its jump.

type opKind int

const (
	opInsn opKind = iota
	opJump
	opCondJump
	opLabel
)

type op struct {
	kind   opKind
	insn   bpf.Instruction
	cond   bpf.JumpTest
	val    uint32
	target string
	label  string
}

type builder struct {
	ops []op
}

func (b *builder) emit(insns ...bpf.Instruction) {
	for _, ins := range insns {
		b.ops = append(b.ops, op{kind: opInsn, insn: ins})
	}
}

func (b *builder) label(name string) {
	b.ops = append(b.ops, op{kind: opLabel, label: name})
}

// jumpTo jumps to target unconditionally.
func (b *builder) jumpTo(target string) {
	b.ops = append(b.ops, op{kind: opJump, target: target})
}

// jumpIf jumps to target when the condition holds comparing val against A, and
// otherwise continues with the instruction after it.
func (b *builder) jumpIf(cond bpf.JumpTest, val uint32, target string) {
	b.ops = append(b.ops, op{kind: opCondJump, cond: cond, val: val, target: target})
}

// layout gives every op its instruction offset and every label its target.
func (b *builder) layout(size []int) ([]int, map[string]int, error) {
	off := make([]int, len(b.ops))
	labels := make(map[string]int)
	at := 0
	for i, o := range b.ops {
		off[i] = at
		if o.kind == opLabel {
			if _, dup := labels[o.label]; dup {
				return nil, nil, fmt.Errorf("seccomp: duplicate label %q", o.label)
			}
			labels[o.label] = at
		}
		at += size[i]
	}
	return off, labels, nil
}

// assemble lays the program out and resolves the labels. Instruction sizes only
// ever grow, so iterating until nothing changes terminates.
func (b *builder) assemble() ([]bpf.Instruction, error) {
	size := make([]int, len(b.ops))
	for i, o := range b.ops {
		if o.kind == opLabel {
			size[i] = 0
		} else {
			size[i] = 1
		}
	}

	for pass := 0; pass <= len(b.ops); pass++ {
		off, labels, err := b.layout(size)
		if err != nil {
			return nil, err
		}

		changed := false
		for i, o := range b.ops {
			if o.kind != opCondJump {
				continue
			}
			target, ok := labels[o.target]
			if !ok {
				return nil, fmt.Errorf("seccomp: jump to unknown label %q", o.target)
			}
			want := 1
			if dist := target - (off[i] + 1); dist < 0 || dist > 255 {
				want = 2
			}
			if size[i] != want {
				size[i] = want
				changed = true
			}
		}
		if changed {
			continue
		}

		out := make([]bpf.Instruction, 0, len(b.ops))
		for i, o := range b.ops {
			switch o.kind {
			case opLabel:
				// Emits nothing; it only names a position.
			case opInsn:
				out = append(out, o.insn)
			case opJump:
				dist := labels[o.target] - (off[i] + 1)
				if dist < 0 {
					return nil, fmt.Errorf("seccomp: jump to %q goes backwards, which cBPF cannot express", o.target)
				}
				out = append(out, bpf.Jump{Skip: uint32(dist)})
			case opCondJump:
				dist := labels[o.target] - (off[i] + 1)
				if dist < 0 {
					return nil, fmt.Errorf("seccomp: jump to %q goes backwards, which cBPF cannot express", o.target)
				}
				if size[i] == 1 {
					out = append(out, bpf.JumpIf{Cond: o.cond, Val: o.val, SkipTrue: uint8(dist), SkipFalse: 0})
					continue
				}
				// On the condition, fall through onto the jump; otherwise
				// skip it and carry on.
				out = append(out,
					bpf.JumpIf{Cond: o.cond, Val: o.val, SkipTrue: 0, SkipFalse: 1},
					bpf.Jump{Skip: uint32(labels[o.target] - (off[i] + 2))},
				)
			}
		}
		return out, nil
	}
	return nil, errors.New("seccomp: jump layout did not settle")
}

// preparedRule is a rule that survived validation, with its action already
// turned into a SECCOMP_RET_* value and its argument conditions detached from
// the profile, because a multiplexed rule is emitted with rewritten arguments.
type preparedRule struct {
	args   []*configs.Arg
	action uint32
}

// ruleGroup is every rule a profile gives for one syscall, in profile order: the
// first whose argument conditions hold decides.
type ruleGroup struct {
	num   uint32
	rules []preparedRule
}

// treeEmitter lays rules out as a balanced binary search over the syscall
// number, so a syscall costs O(log rules) comparisons instead of walking all of
// them. The descent lands on the nearest key rather than necessarily an equal
// one, so each group still checks for equality.
type treeEmitter struct {
	b    *builder
	next int
	// word32 is set for a 32-bit architecture, whose arguments have no high
	// word and are compared the way libseccomp compares them (see archIs32Bit).
	word32 bool
}

func (t *treeEmitter) newLabel(prefix string) string {
	t.next++
	return fmt.Sprintf("%s%d", prefix, t.next)
}

func (t *treeEmitter) emit(groups []ruleGroup, defaultLabel string) {
	if len(groups) == 0 {
		t.b.jumpTo(defaultLabel)
		return
	}
	if len(groups) == 1 {
		t.emitGroup(groups[0], defaultLabel)
		return
	}

	mid := len(groups) / 2
	right := t.newLabel("right")

	// A holds the syscall number here and nothing has clobbered it: a rule is
	// only reached once the descent is over, and it never returns to the tree.
	//
	// JumpGreaterOrEqual compares A against the value, i.e. "nr >= pivot", which
	// is the direction the kernel implements. x/net/bpf's doc comments describe
	// these the other way round, which is worth knowing when reading the
	// conditions below.
	t.b.jumpIf(bpf.JumpGreaterOrEqual, groups[mid].num, right)
	t.emit(groups[:mid], defaultLabel)
	t.b.label(right)
	t.emit(groups[mid:], defaultLabel)
}

func (t *treeEmitter) emitGroup(g ruleGroup, defaultLabel string) {
	// The descent lands on the nearest key, not necessarily an equal one.
	t.b.jumpIf(bpf.JumpNotEqual, g.num, defaultLabel)
	for i, r := range g.rules {
		fail := defaultLabel
		if i+1 < len(g.rules) {
			// Another rule for the same syscall gets a chance.
			fail = t.newLabel("next")
		}
		t.emitRule(r, fail)
		if fail != defaultLabel {
			t.b.label(fail)
		}
	}
}

// emitRule emits one rule: its argument conditions, all of which must hold, and
// then its action. Control jumps to failLabel as soon as one does not.
func (t *treeEmitter) emitRule(r preparedRule, failLabel string) {
	for _, arg := range r.args {
		t.emitCondition(arg, failLabel)
	}
	t.b.emit(bpf.RetConstant{Val: r.action})
}

// argWordOffset is the offset in struct seccomp_data of the low or high 32 bits
// of a syscall argument.
func argWordOffset(index uint, high bool) uint32 {
	off := uint32(seccompDataArgs + seccompDataArgSize*index)
	if high {
		return off + argHighOffset()
	}
	return off + argLowOffset()
}

// emitCondition emits the tests for one argument, jumping to failLabel when the
// condition does not hold and carrying on when it does.
//
// On a 64-bit architecture the whole 64-bit argument is compared, which is what
// libseccomp does and what the profile means: comparing only the low half would
// match 0x10000002a against a rule for 42, and for an allow rule that is
// fail-open. On a 32-bit architecture there is no high half to compare, and
// libseccomp compares only the low word, so this does too; cBPF reads one word
// at a time, so a 64-bit comparison means comparing the high half first.
func (t *treeEmitter) emitCondition(arg *configs.Arg, failLabel string) {
	loadHigh := func() {
		t.b.emit(bpf.LoadAbsolute{Off: argWordOffset(arg.Index, true), Size: 4})
	}
	loadLow := func() {
		t.b.emit(bpf.LoadAbsolute{Off: argWordOffset(arg.Index, false), Size: 4})
	}

	high := uint32(arg.Value >> 32)
	low := uint32(arg.Value)

	switch arg.Op {
	case configs.EqualTo:
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpNotEqual, high, failLabel)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpNotEqual, low, failLabel)

	case configs.NotEqualTo:
		// Only fails when both halves are equal.
		cont := t.newLabel("cont")
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpNotEqual, high, cont)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpEqual, low, failLabel)
		t.b.label(cont)

	case configs.GreaterThan: // arg > value
		cont := t.newLabel("cont")
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpLessThan, high, failLabel)
			t.b.jumpIf(bpf.JumpGreaterThan, high, cont)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpLessOrEqual, low, failLabel)
		t.b.label(cont)

	case configs.GreaterThanOrEqualTo: // arg >= value
		cont := t.newLabel("cont")
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpLessThan, high, failLabel)
			t.b.jumpIf(bpf.JumpGreaterThan, high, cont)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpLessThan, low, failLabel)
		t.b.label(cont)

	case configs.LessThan: // arg < value
		cont := t.newLabel("cont")
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpGreaterThan, high, failLabel)
			t.b.jumpIf(bpf.JumpLessThan, high, cont)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpGreaterOrEqual, low, failLabel)
		t.b.label(cont)

	case configs.LessThanOrEqualTo: // arg <= value
		cont := t.newLabel("cont")
		if !t.word32 {
			loadHigh()
			t.b.jumpIf(bpf.JumpGreaterThan, high, failLabel)
			t.b.jumpIf(bpf.JumpLessThan, high, cont)
		}
		loadLow()
		t.b.jumpIf(bpf.JumpGreaterThan, low, failLabel)
		t.b.label(cont)

	case configs.MaskEqualTo:
		// SCMP_CMP_MASKED_EQ takes the mask first and the value to compare
		// against second: (arg & Value) == ValueTwo. Swapping the two makes the
		// rule match nothing, which matters because the default profile allows
		// clone with (arg0 & CLONE_NEW*) == 0 -- that zero is the value being
		// compared against, not an unset field.
		if !t.word32 {
			loadHigh()
			t.b.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: uint32(arg.Value >> 32)})
			t.b.jumpIf(bpf.JumpNotEqual, uint32(arg.ValueTwo>>32), failLabel)
		}
		loadLow()
		t.b.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: low})
		t.b.jumpIf(bpf.JumpNotEqual, uint32(arg.ValueTwo), failLabel)
	}
}

// pseudoRuleArgs returns the argument conditions for the multiplexed half of a
// socketcall/ipc rule. libseccomp forces argument 0 to the subcall number and
// keeps whatever other argument conditions the rule carried, so a condition
// the profile put on argument 0 is replaced rather than kept.
func pseudoRuleArgs(subcall uint32, args []*configs.Arg) []*configs.Arg {
	out := make([]*configs.Arg, 0, len(args)+1)
	out = append(out, &configs.Arg{Index: 0, Op: configs.EqualTo, Value: uint64(subcall)})
	for _, arg := range args {
		if arg.Index == 0 {
			continue
		}
		out = append(out, arg)
	}
	return out
}

// validateArgs rejects an argument list the compiler cannot express.
func validateArgs(call *configs.Syscall) error {
	for _, arg := range call.Args {
		if arg == nil {
			return fmt.Errorf("nil argument in seccomp rule for %s", call.Name)
		}
		if arg.Index >= seccompDataArgCount {
			return fmt.Errorf("seccomp rule for %s: argument index %d out of range", call.Name, arg.Index)
		}
		switch arg.Op {
		case configs.EqualTo, configs.NotEqualTo,
			configs.GreaterThan, configs.GreaterThanOrEqualTo,
			configs.LessThan, configs.LessThanOrEqualTo,
			configs.MaskEqualTo:
		default:
			return fmt.Errorf("invalid operator %d in seccomp rule for %s", arg.Op, call.Name)
		}
	}
	return nil
}

// hasDuplicateArgIndex reports whether two conditions in one rule name the same
// argument index. runc's cgo path treats that as its cue to split the rule.
func hasDuplicateArgIndex(args []*configs.Arg) bool {
	var seen [seccompDataArgCount]bool
	for _, arg := range args {
		if seen[arg.Index] {
			return true
		}
		seen[arg.Index] = true
	}
	return false
}

// compileArchSection compiles the rules for one architecture, ending in the
// default action. table is the architecture's syscall name -> number map, as
// libseccomp resolves names, and pseudo its multiplexor table (nil when the
// architecture has no multiplexor).
func compileArchSection(config *configs.Seccomp, table map[string]uint32, pseudo map[string]pseudoSyscall, defaultRet uint32, arch string) ([]bpf.Instruction, error) {
	// Grouped by syscall number so the tree can be ordered; the rules within a
	// group keep profile order.
	index := make(map[uint32]int)
	var groups []ruleGroup

	addRule := func(num uint32, rule preparedRule) {
		if at, seen := index[num]; seen {
			groups[at].rules = append(groups[at].rules, rule)
			return
		}
		index[num] = len(groups)
		groups = append(groups, ruleGroup{num: num, rules: []preparedRule{rule}})
	}

	for _, call := range config.Syscalls {
		if call == nil {
			return nil, errors.New("encountered nil syscall while initializing seccomp")
		}
		if len(call.Name) == 0 {
			return nil, errors.New("empty string is not a valid syscall")
		}
		if call.Action == configs.Notify && call.Name == "write" {
			return nil, errors.New("SCMP_ACT_NOTIFY cannot be used for the write syscall")
		}

		action, err := seccompRetAction(call.Action, call.ErrnoRet)
		if err != nil {
			return nil, fmt.Errorf("action in seccomp profile is invalid: %w", err)
		}
		if action == defaultRet {
			// libseccomp's matchCall drops a rule whose action equals the
			// profile's default action regardless of its arguments: the default
			// already says what the rule says, so the rule cannot change the
			// outcome, and keeping it lets it shadow a later, stricter rule for
			// the same syscall. The whole action is compared, not just its kind:
			// two SCMP_ACT_ERRNO rules returning different errnos differ.
			//
			// This is the same check the libseccomp build makes, so the two
			// builds agree on which of two rules for one syscall survives.
			continue
		}
		if err := validateArgs(call); err != nil {
			return nil, err
		}

		ps, isPseudo := pseudo[call.Name]
		num, inTable := table[call.Name]
		if !isPseudo && !inTable {
			// libseccomp cannot resolve the name on this architecture, or
			// resolves it to a pseudo number it adds no rule for, so the cgo
			// build drops the rule. Dropping it here is what keeps the two
			// filters the same; the table is generated from libseccomp so that
			// "cannot resolve" means the same on both sides.
			//
			// It is a warning and not a debug message because the drop is
			// silent otherwise, and a *deny* rule that is dropped is a rule
			// that is not enforced -- fail-open. The usual cause is a
			// libseccomp newer than the one the committed table was generated
			// from, which resolves a name this table lacks; the cgo build then
			// enforces the rule and this build does not. Matching libseccomp's
			// drop is deliberate and stays, so the warning is the only signal
			// an operator gets that the filter is not doing what the profile
			// says.
			logrus.Warnf("seccomp: cannot resolve syscall %q for architecture %s; the rule is dropped and will not be enforced (the name is absent from the generated libseccomp table)", call.Name, arch)
			continue
		}

		// runc's cgo path turns two conditions on one argument into separate
		// rules rather than one rule carrying both, because libseccomp's
		// db_col_rule_add() rejects a second condition on an argument index it
		// has already seen (EINVAL); matchCall therefore gives each condition
		// its own AddRuleConditional. That is OR, not AND, and it is what the
		// kernel actually sees from the cgo build, so it is what this has to
		// compile.
		conditions := [][]*configs.Arg{call.Args}
		if hasDuplicateArgIndex(call.Args) {
			conditions = make([][]*configs.Arg, 0, len(call.Args))
			for _, arg := range call.Args {
				conditions = append(conditions, []*configs.Arg{arg})
			}
		}

		for _, conds := range conditions {
			if isPseudo {
				// The multiplexed rule, with argument 0 forced to the subcall,
				// and, when the architecture has a direct-wired number for the
				// name, a second rule on it. Both are needed: old kernels have
				// only the multiplexor and newer ones accept both.
				addRule(ps.mux, preparedRule{args: pseudoRuleArgs(ps.subcall, conds), action: action})
				if ps.flat != 0 {
					addRule(ps.flat, preparedRule{args: conds, action: action})
				}
				continue
			}
			addRule(num, preparedRule{args: conds, action: action})
		}
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].num < groups[j].num })

	const defaultLabel = "default"
	b := &builder{}
	t := &treeEmitter{b: b, word32: archIs32Bit[arch]}
	b.emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})

	// On the x86_64 ABI, an x32 syscall signals itself with bit 30 of the
	// number, because seccomp_data.arch is AUDIT_ARCH_X86_64 for both ABIs.
	// When the profile lists SCMP_ARCH_X32 there is a section for it and
	// assembleFilter dispatches by the bit, so this section only ever sees
	// x86-64 numbers. When it does not, an x32 syscall is refused here rather
	// than judged with the x86-64 table. 0xffffffff is not a syscall and takes
	// the ordinary path, as it does in libseccomp.
	if arch == "SCMP_ARCH_X86_64" {
		kill, tree := t.newLabel("x32kill"), t.newLabel("tree")
		b.jumpIf(bpf.JumpLessThan, x32SyscallBit, tree)
		b.jumpIf(bpf.JumpNotEqual, ^uint32(0), kill)
		b.jumpTo(tree)
		b.label(kill)
		b.emit(bpf.RetConstant{Val: retKillThread})
		b.label(tree)
	}

	t.emit(groups, defaultLabel)
	b.label(defaultLabel)
	b.emit(bpf.RetConstant{Val: defaultRet})
	return b.assemble()
}
