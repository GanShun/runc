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
	prog      []bpf.Instruction
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
	seen := make(map[uint32]bool, len(arches))

	for _, name := range arches {
		arch, ok := normalizeArch(name)
		if !ok {
			return nil, fmt.Errorf("unknown seccomp architecture %q", name)
		}
		audit := auditArch[arch]
		// Two architectures can share one AUDIT_ARCH value (x32 and x86_64);
		// the first match wins, as in libseccomp.
		if seen[audit] {
			continue
		}
		seen[audit] = true

		table, ok := syscallNumbers[arch]
		if !ok {
			// x/sys/unix carries no table for this architecture (x32, the
			// mips n32 ABIs, 31-bit s390). Leaving it out of the dispatch
			// means the filter's bad-architecture action refuses it, which
			// is fail-closed and better than filtering it with the wrong
			// numbering.
			logrus.Warnf("seccomp: no syscall table for architecture %q, refusing it rather than filtering it", name)
			continue
		}
		prog, err := compileArchSection(config, table, defaultRet)
		if err != nil {
			return nil, err
		}
		sections = append(sections, archSection{auditArch: audit, prog: prog})
	}

	prog := assembleFilter(sections, defaultRet)

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
//	ld  [4]
//	jeq A0 -> 0,1 ; jmp section0
//	jeq A1 -> 0,1 ; jmp section1
//	...
//	ret KILL_PROCESS   ; the arch matched nothing
//	section0:
//	  ...
//	section1:
//	  ...
func assembleFilter(sections []archSection, defaultRet uint32) []bpf.Instruction {
	// The jmp targets are 32-bit, so the architecture tests can reach a
	// section of any size; only the jeq's own skip has to stay small, and it
	// is always 1.
	header := 1 + 2*len(sections) + 1
	starts := make([]int, len(sections))
	offset := header
	for i, s := range sections {
		starts[i] = offset
		offset += len(s.prog)
	}

	prog := make([]bpf.Instruction, 0, offset)
	prog = append(prog, bpf.LoadAbsolute{Off: seccompDataArch, Size: 4})
	for i, s := range sections {
		prog = append(prog, bpf.JumpIf{
			Cond:      bpf.JumpEqual,
			Val:       s.auditArch,
			SkipTrue:  0,
			SkipFalse: 1,
		})
		// This instruction is at index 2*i+2, so it is followed by index
		// 2*i+3; skip from there to the section.
		prog = append(prog, bpf.Jump{Skip: uint32(starts[i] - (2*i + 3))})
	}
	// Reached only when the architecture is none of the above: refusing to
	// run is the safe answer, and matches libseccomp.
	prog = append(prog, bpf.RetConstant{Val: retKillProcess})
	for _, s := range sections {
		prog = append(prog, s.prog...)
	}
	return prog
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

// ruleGroup is every rule a profile gives for one syscall, in profile order: the
// first whose argument conditions hold decides.
type ruleGroup struct {
	num    uint32
	bodies [][]bpf.Instruction
}

// treeEmitter lays rules out as a balanced binary search over the syscall
// number, so a syscall costs O(log rules) comparisons instead of walking all of
// them. The descent lands on the nearest key rather than necessarily an equal
// one, so each group still checks for equality.
type treeEmitter struct {
	b    *builder
	next int
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
	right := fmt.Sprintf("right%d", t.next)
	t.next++

	// A holds the syscall number here and nothing has clobbered it: a leaf body
	// is only reached once the descent is over, and it never returns to the
	// tree.
	//
	// JumpGreaterOrEqual compares A against the value, i.e. "nr >= pivot", which
	// is the direction the kernel implements. x/net/bpf's doc comments describe
	// these the other way round; the arg operator code above follows the
	// encoding too, which is why it is right.
	t.b.jumpIf(bpf.JumpGreaterOrEqual, groups[mid].num, right)
	t.emit(groups[:mid], defaultLabel)
	t.b.label(right)
	t.emit(groups[mid:], defaultLabel)
}

func (t *treeEmitter) emitGroup(g ruleGroup, defaultLabel string) {
	t.b.jumpIf(bpf.JumpNotEqual, g.num, defaultLabel)
	for _, body := range g.bodies {
		t.b.emit(body...)
	}
	// A body with argument conditions falls through to here when they do not
	// hold, so the default action has to be reached from here. A bare action
	// always returns, so the jump would be unreachable code -- and there is one
	// of these per rule in the common case where no rule has conditions.
	if last := g.bodies[len(g.bodies)-1]; len(last) > 1 {
		t.b.jumpTo(defaultLabel)
	}
}

// compileArchSection compiles the rules for one architecture, ending in the
// default action.
func compileArchSection(config *configs.Seccomp, table map[string]uint32, defaultRet uint32) ([]bpf.Instruction, error) {
	// Grouped by syscall number so the tree can be ordered; the bodies within a
	// group keep profile order.
	index := make(map[uint32]int)
	var groups []ruleGroup

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

		body, err := compileRule(call, defaultRet)
		if err != nil {
			return nil, err
		}
		if len(body) == 0 {
			// Redundant rule (same action as the default, no conditions).
			continue
		}
		if len(body) > 0xff {
			// The failing argument tests inside a body skip to its end with an
			// 8-bit offset.
			return nil, fmt.Errorf("seccomp rule for %s is too long (%d instructions)", call.Name, len(body))
		}

		num, ok := table[call.Name]
		if !ok {
			// Not every name in a profile exists on every architecture, and
			// libseccomp resolves names against its own tables. Skipping is
			// what the cgo build does too.
			logrus.Debugf("unknown seccomp syscall %q on this architecture, ignored", call.Name)
			continue
		}

		if at, seen := index[num]; seen {
			groups[at].bodies = append(groups[at].bodies, body)
			continue
		}
		index[num] = len(groups)
		groups = append(groups, ruleGroup{num: num, bodies: [][]bpf.Instruction{body}})
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].num < groups[j].num })

	const defaultLabel = "default"
	b := &builder{}
	b.emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})
	(&treeEmitter{b: b}).emit(groups, defaultLabel)
	b.label(defaultLabel)
	b.emit(bpf.RetConstant{Val: defaultRet})
	return b.assemble()
}

// compileRule builds the body for one syscall: the argument tests (all of
// which must hold) followed by the action. It returns nothing when the rule
// is redundant, so that the caller can drop it.
func compileRule(call *configs.Syscall, defaultRet uint32) ([]bpf.Instruction, error) {
	action, err := seccompRetAction(call.Action, call.ErrnoRet)
	if err != nil {
		return nil, fmt.Errorf("action in seccomp profile is invalid: %w", err)
	}
	if action == defaultRet && len(call.Args) == 0 {
		// Same result as the default action, so the rule can never change the
		// outcome. This compares the whole action rather than just its kind:
		// two SCMP_ACT_ERRNO rules returning different errnos are not the
		// same rule.
		return nil, nil
	}
	if len(call.Args) == 0 {
		return []bpf.Instruction{bpf.RetConstant{Val: action}}, nil
	}

	body := []bpf.Instruction{}
	// failAt records the conditional jumps that abandon the rule, so their
	// skips can be filled in once the body length is known.
	var failAt []int

	for _, arg := range call.Args {
		if arg == nil {
			return nil, fmt.Errorf("nil argument in seccomp rule for %s", call.Name)
		}
		if arg.Index >= seccompDataArgCount {
			return nil, fmt.Errorf("seccomp rule for %s: argument index %d out of range", call.Name, arg.Index)
		}

		// seccomp only compares the low 32 bits of an argument, as does
		// libseccomp; the high half is simply not expressible in cBPF.
		body = append(body, bpf.LoadAbsolute{
			Off:  uint32(seccompDataArgs+seccompDataArgSize*arg.Index) + argLowOffset(),
			Size: 4,
		})

		// The condition below is the one that makes the rule *not* match;
		// the rule is skipped when it is true. The comparison operators are
		// expressed as A <op> K, which is what the cBPF jumps implement.
		var (
			fail   bpf.JumpTest
			expect uint32
		)
		switch arg.Op {
		case configs.EqualTo:
			fail, expect = bpf.JumpNotEqual, uint32(arg.Value)
		case configs.NotEqualTo:
			fail, expect = bpf.JumpEqual, uint32(arg.Value)
		case configs.GreaterThan:
			fail, expect = bpf.JumpLessOrEqual, uint32(arg.Value)
		case configs.GreaterThanOrEqualTo:
			fail, expect = bpf.JumpLessThan, uint32(arg.Value)
		case configs.LessThan:
			fail, expect = bpf.JumpGreaterOrEqual, uint32(arg.Value)
		case configs.LessThanOrEqualTo:
			fail, expect = bpf.JumpGreaterThan, uint32(arg.Value)
		case configs.MaskEqualTo:
			// SCMP_CMP_MASKED_EQ takes the mask first and the value to
			// compare against second: (arg & Value) == ValueTwo. Swapping
			// the two makes the rule match nothing, which matters because
			// the default profile allows clone with
			// (arg0 & CLONE_NEW*) == 0 -- ValueTwo being zero there is not
			// a mistake, it is the value being compared against.
			body = append(body, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: uint32(arg.Value)})
			fail, expect = bpf.JumpNotEqual, uint32(arg.ValueTwo)
		default:
			return nil, fmt.Errorf("invalid operator %d in seccomp rule for %s", arg.Op, call.Name)
		}

		failAt = append(failAt, len(body))
		body = append(body, bpf.JumpIf{Cond: fail, Val: expect})
	}

	body = append(body, bpf.RetConstant{Val: action})
	// Every failing test jumps past the action, i.e. to the end of the body.
	for _, i := range failAt {
		j := body[i].(bpf.JumpIf)
		j.SkipTrue = uint8(len(body) - i - 1)
		j.SkipFalse = 0
		body[i] = j
	}
	return body, nil
}
