//go:build linux && amd64

// Package main is a differential harness for runc's two seccomp builds.
//
// The same source is compiled twice:
//
//	CGO_ENABLED=0                       -> libcontainer/seccomp compiles the
//	                                       filter in Go (seccomp_nocgo.go)
//	CGO_ENABLED=1 -tags seccomp         -> libcontainer/seccomp hands the
//	                                       profile to libseccomp
//
// Both binaries are then run inside a QEMU VM and their real, kernel-observed
// behaviour is compared per (profile, probe) pair. The existing tests compare
// the two BPF programs in the x/net/bpf interpreter, so they cannot see
// anything the kernel does differently -- and they skip the cases where the two
// builds are known not to agree.
//
// Everything here is deliberately isolated from the host: installing a seccomp
// filter is irreversible for the process that does it, so every filter is
// installed in a short-lived child process inside the VM, never on the host.
package main

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// Abi is the syscall entry path a probe uses. The seccomp architecture the
// kernel reports depends on it, not on the process's own architecture: int
// 0x80 from a 64-bit process reports AUDIT_ARCH_I386, and a syscall number
// with bit 30 set reports AUDIT_ARCH_X86_64 with an x32 number.
type Abi string

const (
	AbiNative Abi = "amd64"
	AbiI386   Abi = "i386"
	AbiX32    Abi = "x32"
)

// Rule mirrors configs.Syscall but stays declarative so a case is data rather
// than code.
type Rule struct {
	Name     string
	Action   configs.Action
	Errno    uint // used when Action is Errno/Trace
	HasErrno bool
	Args     []Arg
}

type Arg struct {
	Index    uint
	Op       configs.Operator
	Value    uint64
	ValueTwo uint64
}

// Case is one seccomp profile plus the probes worth running under it.
type Case struct {
	Name string
	Why  string // what this case is looking for
	// Arch is configs.Seccomp.Architectures. The native architecture is added
	// by both builds, so it does not need listing.
	Arch          []string
	DefaultAction configs.Action
	DefaultErrno  uint
	HasDefaultErr bool
	Flags         []specs.LinuxSeccompFlag
	Rules         []Rule
	// NoExitRules suppresses the automatic exit/exit_group allow rules. Every
	// case gets them so a blocked exit_group cannot turn every probe into a
	// timeout; cases about the -ENOSYS boundary need them gone, because the
	// rules raise the largest syscall number in the profile.
	NoExitRules bool
	// Probes adds probes to the core set for this case only.
	Probes []string
}

const errnoEPERM = 1
const errnoEACCES = 13
const errnoENOSYS = 38

func ptr(v uint) *uint { return &v }

// buildConfig turns a Case into the configs.Seccomp both builds consume.
func (c *Case) buildConfig() *configs.Seccomp {
	cfg := &configs.Seccomp{
		DefaultAction: c.DefaultAction,
		Architectures: c.Arch,
		Flags:         c.Flags,
	}
	if c.HasDefaultErr {
		cfg.DefaultErrnoRet = ptr(c.DefaultErrno)
	}
	rules := make([]Rule, 0, len(c.Rules)+2)
	rules = append(rules, c.Rules...)
	if !c.NoExitRules {
		rules = append(rules,
			Rule{Name: "exit", Action: configs.Allow},
			Rule{Name: "exit_group", Action: configs.Allow},
		)
	}
	for _, r := range rules {
		sc := &configs.Syscall{Name: r.Name, Action: r.Action}
		if r.HasErrno {
			sc.ErrnoRet = ptr(r.Errno)
		}
		for _, a := range r.Args {
			sc.Args = append(sc.Args, &configs.Arg{
				Index:    a.Index,
				Op:       a.Op,
				Value:    a.Value,
				ValueTwo: a.ValueTwo,
			})
		}
		cfg.Syscalls = append(cfg.Syscalls, sc)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// The probe corpus.
//
// A probe is one raw syscall invocation. Its outcome is reported as the errno
// the syscall returned, or as a signal if the process was killed. Comparing
// against the unfiltered baseline is what makes the report readable: a probe
// that naturally returns EBADF and returns EBADF under a filter is unchanged,
// while one that naturally returns EBADF and returns EPERM has been acted on.
//
// Two rules for choosing probes:
//
//   - The value a probe passes must not be a descriptor the harness itself
//     needs. The result page is fd 3, so probes use 4, 12345 or a 64-bit value
//     whose low half is 12345, never 0, 1 or 3.
//   - A probe's natural result must be distinguishable from the errnos a
//     filter is likely to return, or the observation says nothing.
// ---------------------------------------------------------------------------

type Probe struct {
	Name string
	Abi  Abi
	// Core probes run under every case. Everything else is asked for by name
	// through Case.Probes.
	Core bool
	// Survivor spawns a second thread that outlives the probe thread and
	// records that it did. It is how KILL_THREAD (one thread dies, the process
	// lives) is told apart from KILL_PROCESS (everything dies).
	Survivor bool
	// Nr is the syscall number in the probe's own numbering.
	Nr func() uintptr
	// Args are passed to the syscall. Setup, if set, runs before the filter is
	// installed and may record a file descriptor for Args to use.
	Args  func() [6]uintptr
	Setup func() error
}

// amd64 asm/unistd_64.h numbers. vmdiff cannot read the package-private
// syscall tables, so the numbers it probes with are written out here.
const (
	nrRead        = 0
	nrClose       = 3
	nrLseek       = 8
	nrGetpid      = 39
	nrOpenat      = 257
	nrStatx       = 332
	nrClone       = 56
	nrClone3      = 435
	nrCachestat   = 451
	nrFutexWake   = 454
	nrStatmount   = 457
	nrListmount   = 458
	nrLsmListMods = 461
	nrMseal       = 462
	nrUretprobe   = 335

	// i386 numbers (asm/unistd_32.h).
	nrI386Read       = 3
	nrI386Socketcall = 102
	nrI386Socket     = 359
	nrI386Getpid     = 20

	// x32 shares the amd64 table behind bit 30.
	x32Bit = 1 << 30

	// fdArg is the value the argument-comparison probes pass as a descriptor.
	// It is not a real descriptor, so the natural result is EBADF, and it is
	// far from the descriptors the harness itself holds.
	fdArg = 12345
	// fdArg64 has fdArg in its low half and 3 in its high half: a filter that
	// only compared the low 32 bits would treat it as fdArg.
	fdArg64 = uint64(3)<<32 | fdArg
	// fdSmall is a value below fdArg that is also not an open descriptor. 4 is
	// not usable: os/exec leaves it open in the child.
	fdSmall = 12344
)

var fdForSetup uintptr = ^uintptr(0)

var probes = []Probe{
	{Name: "getpid", Core: true, Abi: AbiNative,
		Nr: func() uintptr { return nrGetpid }},

	// Argument-comparison subjects. All of them are naturally EBADF, so any
	// errno a filter returns stands out.
	{Name: "close(-1)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrClose },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0)} }},
	{Name: "close(12344)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrClose },
		Args: func() [6]uintptr { return [6]uintptr{fdSmall} }},
	{Name: "close(12345)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrClose },
		Args: func() [6]uintptr { return [6]uintptr{fdArg} }},
	{Name: "close(3<<32|12345)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrClose },
		Args: func() [6]uintptr { return [6]uintptr{uintptr(fdArg64)} }},
	{Name: "close(valid)", Core: true, Abi: AbiNative,
		Nr: func() uintptr { return nrClose },
		Setup: func() error {
			fd, err := openDevNull()
			if err != nil {
				return err
			}
			fdForSetup = uintptr(fd)
			return nil
		},
		Args: func() [6]uintptr { return [6]uintptr{fdForSetup} }},

	// A syscall libseccomp knows a name for that x/sys does not (_llseek).
	{Name: "lseek(12345)", Abi: AbiNative,
		Nr:   func() uintptr { return nrLseek },
		Args: func() [6]uintptr { return [6]uintptr{fdArg, 0, 0} }},
	{Name: "read(-1)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrRead },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0), 0, 0} }},
	{Name: "openat(NULL)", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrOpenat },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(99), 0, 0} }}, // AT_FDCWD, NULL
	{Name: "statx", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrStatx },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(99), 0, 0, 0, 0} }},

	// clone3 is the syscall libc falls back *from*, and clone the one it falls
	// back to; both matter for the -ENOSYS stub.
	{Name: "clone3", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrClone3 },
		Args: func() [6]uintptr { return [6]uintptr{0, 0} }},

	// Kernel 6.8 syscalls that libseccomp 2.5.5 does not know by name, plus
	// one it does, so name coverage can be seen directly.
	{Name: "cachestat", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrCachestat },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0), 0, 0, 0, 0} }},
	{Name: "statmount", Core: true, Abi: AbiNative,
		Nr:   func() uintptr { return nrStatmount },
		Args: func() [6]uintptr { return [6]uintptr{0, 0, 0, 0} }},
	{Name: "listmount", Abi: AbiNative,
		Nr:   func() uintptr { return nrListmount },
		Args: func() [6]uintptr { return [6]uintptr{0, 0, 0, 0} }},
	{Name: "lsm_list_modules", Abi: AbiNative,
		Nr:   func() uintptr { return nrLsmListMods },
		Args: func() [6]uintptr { return [6]uintptr{0, 0, 0} }},
	{Name: "mseal", Abi: AbiNative,
		Nr:   func() uintptr { return nrMseal },
		Args: func() [6]uintptr { return [6]uintptr{0, 0, 0} }},
	{Name: "futex_wake", Abi: AbiNative,
		Nr:   func() uintptr { return nrFutexWake },
		Args: func() [6]uintptr { return [6]uintptr{0, 0, 0, 0, 0} }},
	{Name: "uretprobe", Abi: AbiNative,
		Nr:   func() uintptr { return nrUretprobe },
		Args: func() [6]uintptr { return [6]uintptr{0} }},

	// The -ENOSYS boundary. Both are ENOSYS naturally, so a filter that
	// returns the default action instead is visible.
	{Name: "nr=1000", Core: true, Abi: AbiNative,
		Nr: func() uintptr { return 1000 }},
	{Name: "nr=9999", Core: true, Abi: AbiNative,
		Nr: func() uintptr { return 9999 }},

	// The i386 and x32 entry paths.
	{Name: "i386 getpid", Abi: AbiI386,
		Nr: func() uintptr { return nrI386Getpid }},
	{Name: "i386 read(-1)", Abi: AbiI386,
		Nr:   func() uintptr { return nrI386Read },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0), 0, 0} }},
	{Name: "i386 socket", Abi: AbiI386,
		Nr:   func() uintptr { return nrI386Socket },
		Args: func() [6]uintptr { return [6]uintptr{2, 1, 0} }},
	{Name: "i386 socketcall(SOCKET)", Abi: AbiI386,
		Nr:   func() uintptr { return nrI386Socketcall },
		Args: func() [6]uintptr { return [6]uintptr{1, 0} }},
	// 360 is the i386 socketpair number and one above the flat i386 socket
	// number (359). It is how a -ENOSYS boundary computed from the flat number of
	// a multiplexed name is told from one computed from the pseudo number.
	{Name: "i386 nr=360", Abi: AbiI386,
		Nr: func() uintptr { return 360 }},
	{Name: "x32 read", Abi: AbiX32,
		Nr:   func() uintptr { return nrRead | x32Bit },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0), 0, 0} }},
	{Name: "x32 getpid", Abi: AbiX32,
		Nr: func() uintptr { return nrGetpid | x32Bit }},
	{Name: "x32 0xffffffff", Abi: AbiX32,
		Nr: func() uintptr { return 0xffffffff }},

	// KILL_THREAD vs KILL_PROCESS detectors.
	{Name: "survivor getpid", Core: true, Abi: AbiNative, Survivor: true,
		Nr: func() uintptr { return nrGetpid }},
	{Name: "survivor close(-1)", Abi: AbiNative, Survivor: true,
		Nr:   func() uintptr { return nrClose },
		Args: func() [6]uintptr { return [6]uintptr{^uintptr(0)} }},
	{Name: "survivor x32 getpid", Abi: AbiX32, Survivor: true,
		Nr: func() uintptr { return nrGetpid | x32Bit }},
}

// ---------------------------------------------------------------------------
// The profile corpus.
// ---------------------------------------------------------------------------

func cases() []Case {
	eq := configs.EqualTo
	ne := configs.NotEqualTo
	gt := configs.GreaterThan
	ge := configs.GreaterThanOrEqualTo
	lt := configs.LessThan
	le := configs.LessThanOrEqualTo
	me := configs.MaskEqualTo

	// A rule that denies one syscall unless its argument matches, used by the
	// argument-comparison cases. The default is Allow, so "the rule did not
	// match" is observable as the syscall running, and "it matched" as EACCES.
	deny := func(op configs.Operator, value, valueTwo uint64) []Rule {
		return []Rule{{Name: "close", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
			Args: []Arg{{Index: 0, Op: op, Value: value, ValueTwo: valueTwo}}}}
	}

	return []Case{
		// --- baselines -------------------------------------------------
		{
			Name:          "allow-all",
			Why:           "no rule can change the outcome; every probe should equal the unfiltered baseline",
			DefaultAction: configs.Allow,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name:          "errno-all",
			Why:           "default Errno with no rules: the -ENOSYS stub must not be emitted when the profile mentions nothing",
			DefaultAction: configs.Errno,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name:          "kill-all",
			Why:           "every syscall killed; the survivor probe reports whether the process or only the thread died",
			DefaultAction: configs.Kill,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name:          "killprocess-all",
			Why:           "KILL_PROCESS must take every thread with it",
			DefaultAction: configs.KillProcess,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name:          "trap-all",
			Why:           "TRAP raises SIGSYS; the Go runtime turns that into a panic, so both builds should look the same",
			DefaultAction: configs.Trap,
			NoExitRules:   true,
		},
		{
			Name:          "log-all",
			Why:           "LOG allows and logs; must equal the baseline",
			DefaultAction: configs.Log,
			NoExitRules:   true,
		},
		{
			Name:          "trace-all",
			Why:           "TRACE with no tracer attached: what does the kernel do with the syscall?",
			DefaultAction: configs.Trace,
			NoExitRules:   true,
		},

		// --- the -ENOSYS stub boundary --------------------------------
		{
			Name:          "stub-boundary-openat",
			Why:           "largest syscall in the profile is openat=257; above it ENOSYS, below it the default",
			DefaultAction: configs.Errno,
			Rules:         []Rule{{Name: "openat", Action: configs.Allow}},
			NoExitRules:   true,
		},
		{
			Name: "stub-boundary-statmount",
			Why: "the same with the boundary at statmount=457. libseccomp 2.5.5 " +
				"has no name for statmount, so its own boundary computation sees " +
				"no syscalls at all and emits no stub",
			DefaultAction: configs.Errno,
			Rules:         []Rule{{Name: "statmount", Action: configs.Allow}},
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name: "stub-boundary-redundant-rule",
			Why: "a rule whose action equals the default but which carries " +
				"arguments is skipped by libseccomp (callAct == defAct) but kept " +
				"by the Go compiler (which only skips argless rules), so the " +
				"largest syscall number -- and therefore the stub boundary -- " +
				"differs between the builds",
			DefaultAction: configs.Errno,
			Rules: []Rule{
				{Name: "statmount", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM,
					Args: []Arg{{Index: 0, Op: eq, Value: 0}}},
				{Name: "openat", Action: configs.Allow},
			},
			NoExitRules: true,
		},
		{
			Name: "stub-boundary-libc-fallback",
			Why: "the profile allows clone but not clone3, and names statmount, " +
				"which only the Go table knows. The Go stub boundary is 457 and " +
				"the libseccomp one is 56, so clone3 gets the default action " +
				"from one build and ENOSYS from the other -- and ENOSYS is what " +
				"makes libc retry with clone, which this profile allows",
			DefaultAction: configs.Errno,
			Rules: []Rule{
				{Name: "clone", Action: configs.Allow},
				{Name: "statmount", Action: configs.Allow},
			},
			NoExitRules: true,
		},
		{
			Name: "stub-suppressed-by-enosys-default",
			Why: "DefaultErrnoRet ENOSYS does not suppress the stub, because the " +
				"check compares against the encoded SECCOMP_RET_ERRNO|ENOSYS " +
				"constant rather than the errno. Both builds share the quirk, so " +
				"this is a control, not a divergence",
			DefaultAction: configs.Errno,
			HasDefaultErr: true,
			DefaultErrno:  errnoENOSYS,
			Rules:         []Rule{{Name: "openat", Action: configs.Allow}},
			NoExitRules:   true,
		},
		{
			Name: "stub-suppressed-by-encoded-enosys-default",
			Why: "the same with the encoded constant (0x50026=327718) the check " +
				"actually compares against; here the stub really is suppressed",
			DefaultAction: configs.Errno,
			HasDefaultErr: true,
			DefaultErrno:  0x50026,
			Rules:         []Rule{{Name: "openat", Action: configs.Allow}},
			NoExitRules:   true,
		},
		{
			Name: "stub-with-exit-rules",
			Why: "the same as stub-boundary-statmount but with the exit rules " +
				"kept, which puts the libseccomp boundary at exit_group=231 and " +
				"leaves openat (257) between the two boundaries",
			DefaultAction: configs.Errno,
			Rules:         []Rule{{Name: "statmount", Action: configs.Allow}},
		},

		{
			Name: "stub-boundary-pseudo-socket",
			Why: "a multiplexed name on an x86 section under a restrictive " +
				"default. libseccomp resolves socket to the pseudo number -101, " +
				"which is negative and so cannot raise the -ENOSYS boundary: " +
				"libseccomp emits no stub for the i386 section and an i386 " +
				"syscall above the flat socket number (359) takes the default " +
				"action. A boundary computed from the flat number would emit a " +
				"stub and answer ENOSYS there",
			Arch:          []string{"x86"},
			DefaultAction: configs.Errno,
			Rules:         []Rule{{Name: "socket", Action: configs.Allow}},
			NoExitRules:   true,
			Probes:        []string{"i386 socket", "i386 socketcall(SOCKET)", "i386 nr=360"},
		},

		// --- rule ordering and duplicate syscalls ----------------------
		{
			Name: "duplicate-rules-allow-then-errno",
			Why: "two rules for one syscall with the same argument: the Go " +
				"compiler takes the first matching rule in profile order, " +
				"libseccomp drops the ALLOW one as redundant and keeps the " +
				"ERRNO. If so, the Go build is fail-open here",
			DefaultAction: configs.Allow,
			Rules: []Rule{
				{Name: "close", Action: configs.Allow, Args: []Arg{{Index: 0, Op: eq, Value: fdArg}}},
				{Name: "close", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
					Args: []Arg{{Index: 0, Op: eq, Value: fdArg}}},
			},
		},
		{
			Name:          "duplicate-rules-errno-then-allow",
			Why:           "the reverse order, which both builds should agree on",
			DefaultAction: configs.Allow,
			Rules: []Rule{
				{Name: "close", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
					Args: []Arg{{Index: 0, Op: eq, Value: fdArg}}},
				{Name: "close", Action: configs.Allow, Args: []Arg{{Index: 0, Op: eq, Value: fdArg}}},
			},
		},
		{
			Name: "duplicate-rules-allow-argless",
			Why: "the argless form: both builds drop the redundant ALLOW, so the " +
				"ERRNO applies; a control",
			DefaultAction: configs.Allow,
			Rules: []Rule{
				{Name: "close", Action: configs.Allow},
				{Name: "close", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES},
			},
		},
		{
			Name: "redundant-argful-errno-rule",
			Why: "an argful rule whose action and errno equal the default: " +
				"libseccomp drops it and the Go compiler keeps it, which changes " +
				"the stub boundary",
			DefaultAction: configs.Errno,
			Rules: []Rule{
				{Name: "statmount", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM,
					Args: []Arg{{Index: 0, Op: eq, Value: 0}}},
			},
		},
		{
			Name: "arg-same-index-twice",
			Why: "two conditions on one argument. The Go compiler ANDs them, so " +
				"contradictory values never match; runc's cgo path turns them " +
				"into two separate rules (the old behaviour), so either value " +
				"matches",
			DefaultAction: configs.Allow,
			Rules: []Rule{{Name: "close", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
				Args: []Arg{
					{Index: 0, Op: eq, Value: fdArg},
					{Index: 0, Op: eq, Value: fdArg + 1},
				}}},
		},

		// --- argument comparisons -------------------------------------
		{
			Name:          "arg-eq-low32-only",
			Why:           "a 64-bit argument matching a small value only in its low half must not match",
			DefaultAction: configs.Allow,
			Rules:         deny(eq, fdArg, 0),
		},
		{
			Name:          "arg-eq-64bit",
			Why:           "the same comparison against the full 64-bit value, which must match",
			DefaultAction: configs.Allow,
			Rules:         deny(eq, fdArg64, 0),
		},
		{
			Name:          "arg-ne",
			Why:           "NotEqualTo must fail when both halves are equal",
			DefaultAction: configs.Allow,
			Rules:         deny(ne, fdArg, 0),
		},
		{
			Name:          "arg-gt",
			Why:           "GreaterThan is unsigned, so -1 is greater and fdArg is not",
			DefaultAction: configs.Allow,
			Rules:         deny(gt, fdArg, 0),
		},
		{
			Name:          "arg-ge",
			Why:           "GreaterThanOrEqualTo must include equality",
			DefaultAction: configs.Allow,
			Rules:         deny(ge, fdArg, 0),
		},
		{
			Name:          "arg-lt",
			Why:           "LessThan must exclude equality",
			DefaultAction: configs.Allow,
			Rules:         deny(lt, fdArg, 0),
		},
		{
			Name:          "arg-le",
			Why:           "LessThanOrEqualTo must include equality",
			DefaultAction: configs.Allow,
			Rules:         deny(le, fdArg, 0),
		},
		{
			Name:          "arg-masked-zero",
			Why:           "the containerd clone shape: (arg0 & MASK) == 0",
			DefaultAction: configs.Errno,
			Rules: []Rule{{Name: "close", Action: configs.Allow,
				Args: []Arg{{Index: 0, Op: me, Value: 0xff00, ValueTwo: 0}}}},
		},
		{
			Name:          "arg-masked-highbits",
			Why:           "MaskEqualTo where both the mask and the value live in the high 32 bits",
			DefaultAction: configs.Allow,
			Rules:         deny(me, 0xff00000000, 0x300000000),
		},
		{
			Name:          "arg-masked-high-and-low",
			Why:           "a mask spanning both halves",
			DefaultAction: configs.Allow,
			Rules:         deny(me, 0xff000000ff, 0x30000000d),
		},
		{
			Name:          "arg-index-5",
			Why:           "the last argument slot, to check the offset arithmetic",
			DefaultAction: configs.Allow,
			Rules: []Rule{{Name: "read", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
				Args: []Arg{{Index: 5, Op: eq, Value: 0}}}},
		},
		{
			Name:          "arg-two-on-one-syscall",
			Why:           "two conditions on different arguments must both hold",
			DefaultAction: configs.Allow,
			Rules: []Rule{{Name: "read", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES,
				Args: []Arg{
					{Index: 0, Op: eq, Value: ^uint64(0)},
					{Index: 2, Op: eq, Value: 0},
				}}},
		},

		// --- syscall name coverage ------------------------------------
		{
			Name: "name-statmount-block",
			Why: "libseccomp 2.5.5 has no name for statmount (457 in kernel " +
				"6.8) but the Go table does: the Go build blocks it, the " +
				"libseccomp build drops the rule",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "statmount", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name:          "name-listmount-block",
			Why:           "the same for listmount (458)",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "listmount", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"listmount"},
		},
		{
			Name:          "name-lsm-list-modules-block",
			Why:           "the same for lsm_list_modules (461)",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "lsm_list_modules", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"lsm_list_modules"},
		},
		{
			Name:          "name-futex-wake-block",
			Why:           "futex_wake (454) exists in the kernel and in libseccomp; control",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "futex_wake", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"futex_wake"},
		},
		{
			Name:          "name-cachestat-block",
			Why:           "cachestat (451) is in both tables; control",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "cachestat", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
		},
		{
			Name: "name-uretprobe-block",
			Why: "uretprobe (335) is in the x/sys table but not in libseccomp's, " +
				"and the kernel in this VM has no such syscall, so the rules " +
				"differ without an observable effect",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "uretprobe", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"uretprobe"},
		},
		{
			Name: "name-llseek-block",
			Why: "the reverse of the statmount case: libseccomp has a name for " +
				"_llseek on amd64 (as a pseudo-syscall) and x/sys does not, so a " +
				"rule naming it is dropped by the Go build. libseccomp either " +
				"rewrites it to lseek or refuses it",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "_llseek", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
			Probes:        []string{"lseek(12345)"},
		},
		{
			Name: "name-socketcall-block",
			Why: "socketcall has no amd64 syscall: libseccomp may refuse the rule " +
				"or map it, the Go build drops it",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "socketcall", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
		},
		{
			Name:          "name-unknown-block",
			Why:           "a name neither side knows: both drop it, control",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "no_such_syscall_xyz", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
		},
		{
			Name: "name-newfstatat-block",
			Why: "newfstatat is a name libseccomp prefers to fstatat: an " +
				"alias-resolution difference would show up here",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "newfstatat", Action: configs.Errno, HasErrno: true, Errno: errnoEPERM}},
		},

		// --- architectures --------------------------------------------
		{
			Name:          "arch-no-x32",
			Why:           "amd64 only: what happens to an x32-numbered syscall",
			DefaultAction: configs.Errno,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name: "arch-x32-listed",
			Why: "x32 listed explicitly: the Go build has no x32 syscall table " +
				"and refuses x32 numbers, while libseccomp filters them with its " +
				"own table",
			Arch:          []string{"x32"},
			DefaultAction: configs.Allow,
			NoExitRules:   true,
			Rules:         []Rule{{Name: "read", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES}},
			Probes:        []string{"x32 read", "x32 getpid", "survivor x32 getpid"},
		},
		{
			Name: "arch-x86-listed",
			Why: "an i386 section: libseccomp resolves socket through the " +
				"socketcall pseudo-syscall, the Go build uses the flat i386 number",
			Arch:          []string{"x86"},
			DefaultAction: configs.Allow,
			NoExitRules:   true,
			Rules:         []Rule{{Name: "socket", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES}},
			Probes:        []string{"i386 socket", "i386 socketcall(SOCKET)"},
		},
		{
			Name:          "arch-x86-read",
			Why:           "an i386 rule for a syscall both tables number the same: control",
			Arch:          []string{"x86"},
			DefaultAction: configs.Allow,
			NoExitRules:   true,
			Rules:         []Rule{{Name: "read", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES}},
		},
		{
			Name:          "arch-native-listed",
			Why:           "the native architecture listed explicitly, as containerd's default profile does",
			Arch:          []string{"amd64"},
			DefaultAction: configs.Errno,
			Rules:         []Rule{{Name: "openat", Action: configs.Allow}},
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name: "arch-foreign-only",
			Why: "an architecture that is not the one running: both builds " +
				"should still filter the native one. libseccomp refuses to add " +
				"an incompatible architecture, the Go build ignores it",
			Arch:          []string{"arm64"},
			DefaultAction: configs.Errno,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},
		{
			Name: "arch-mips64n32-listed",
			Why: "an architecture the Go build has no syscall table for and " +
				"libseccomp refuses to add to an amd64 filter: the Go build " +
				"installs a filter, the libseccomp build fails outright",
			Arch:          []string{"mips64n32"},
			DefaultAction: configs.Errno,
			NoExitRules:   true,
			Probes:        []string{"i386 getpid", "i386 read(-1)", "i386 socketcall(SOCKET)", "x32 read", "x32 getpid"},
		},

		// --- KILL_THREAD vs KILL_PROCESS -------------------------------
		{
			Name:          "detect-kill-thread-rule",
			Why:           "KILL_THREAD must kill only the offending thread; the survivor probe reports whether the process lived",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.KillThread}},
			Probes:        []string{"survivor close(-1)", "survivor getpid"},
		},
		{
			Name:          "detect-kill-process-rule",
			Why:           "KILL_PROCESS must take every thread with it, so the survivor must not report",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.KillProcess}},
			Probes:        []string{"survivor close(-1)", "survivor getpid"},
		},
		{
			Name:          "detect-kill-default",
			Why:           "the same for a KILL default action",
			DefaultAction: configs.Kill,
			NoExitRules:   true,
			Probes:        []string{"survivor close(-1)", "survivor getpid"},
		},
		{
			Name:          "detect-killprocess-default",
			Why:           "the same for a KILL_PROCESS default action",
			DefaultAction: configs.KillProcess,
			NoExitRules:   true,
			Probes:        []string{"survivor close(-1)", "survivor getpid"},
		},
		{
			Name: "detect-x32-kill",
			Why: "the Go build's x32 guard is a KILL_THREAD; if libseccomp uses " +
				"KILL_PROCESS for the same guard the survivor tells them apart",
			Arch:          []string{"x32"},
			DefaultAction: configs.Allow,
			NoExitRules:   true,
			Rules:         []Rule{{Name: "read", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES}},
			Probes:        []string{"survivor x32 getpid", "survivor getpid"},
		},

		// --- actions ---------------------------------------------------
		{
			Name:          "action-errno-custom",
			Why:           "a per-rule errno distinct from the default's",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "getpid", Action: configs.Errno, HasErrno: true, Errno: errnoEACCES}},
		},
		{
			Name:          "action-errno-default-custom",
			Why:           "DefaultErrnoRet other than EPERM",
			DefaultAction: configs.Errno,
			HasDefaultErr: true,
			DefaultErrno:  errnoEACCES,
			NoExitRules:   true,
		},
		{
			Name:          "action-kill-thread",
			Why:           "KILL_THREAD as a rule action",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.KillThread}},
		},
		{
			Name:          "action-kill-process",
			Why:           "KILL_PROCESS as a rule action",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.KillProcess}},
		},
		{
			Name:          "action-trap",
			Why:           "TRAP as a rule action",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.Trap}},
		},
		{
			Name:          "action-trace",
			Why:           "TRACE as a rule action with no tracer",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.Trace, HasErrno: true, Errno: errnoEPERM}},
		},
		{
			Name:          "action-notify",
			Why:           "NOTIFY installs a listener; the probe should block on both builds",
			DefaultAction: configs.Allow,
			Rules:         []Rule{{Name: "close", Action: configs.Notify}},
			Probes:        []string{"getpid"},
		},
	}
}

// caseNames is used by --list.
func caseNames() []string {
	cs := cases()
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

// ---------------------------------------------------------------------------

func openDevNull() (int, error) {
	f, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	return int(f.Fd()), nil
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vmdiff: "+format+"\n", args...)
	os.Exit(254)
}
