//go:build linux && cgo && seccomp

// Package gen generates the syscall name -> number and multiplexor tables the
// cgo-free seccomp compiler resolves names with, and which are committed as
// libcontainer/seccomp/libseccomp_linux.go.
//
// The cgo build never resolves a name itself: runc hands the name to
// libseccomp, which looks it up in its own hand-maintained per-architecture
// table. The cgo-free build has no libseccomp, so it must carry a copy of that
// table, and the copy has to be exact: a name one side resolves and the other
// does not is a rule one build enforces and the other silently drops, and a
// name the two resolve to different numbers is two different filters.
//
// The table is therefore extracted from libseccomp itself, through its public
// name-resolution API, rather than from the kernel headers (which is what
// syscalls_linux.go carries, and where the two sets differ). For each
// architecture:
//
//   - every number libseccomp can name is enumerated with
//     seccomp_syscall_resolve_num_arch, which gives the direct-wired number of
//     each name -- the number libseccomp's abi_rule_add() calls the "demuxed"
//     number for a multiplexed name;
//   - every name in the kernel-header tables, plus every name found by the
//     enumeration and by scanning libseccomp's negative pseudo-syscall range,
//     is resolved with seccomp_syscall_resolve_name_arch, which is the call the
//     cgo build's GetSyscallFromName ultimately makes.
//
// A name libseccomp resolves to a non-negative number goes into
// libseccompSyscalls. A name it resolves to a socketcall/ipc multiplexing
// pseudo number goes into libseccompPseudo, with the multiplexor, the subcall
// number abi_rule_add() puts in argument 0, and the direct-wired number from
// the enumeration. A name it resolves to any other negative number is left out
// entirely, because abi_rule_add() adds no rule for it either (the rule can
// never match seccomp_data.nr), so dropping it is what libseccomp does.
//
// The generated file is committed Go source: the CGO_ENABLED=0 build never
// needs libseccomp, at build time or at run time. Regenerating it needs cgo and
// libseccomp, and is deliberate: Generate refuses to run against a libseccomp
// whose version differs from PinnedLibseccompVersion, so the committed table
// cannot come from whatever library happens to be installed on the machine
// doing the build.
//
// It is a library rather than a command so that the drift test in
// libcontainer/seccomp can regenerate the tables in memory and compare them
// byte for byte with the committed file. The command in the parent directory is
// a thin wrapper around Generate.
package gen

import (
	"bufio"
	"bytes"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// PinnedLibseccompVersion is the libseccomp version the committed tables were
// generated from. Bumping it is a deliberate act -- edit this constant and then
// regenerate the committed file against a libseccomp of exactly that version
// -- and Generate refuses to run when the linked libseccomp differs, so a
// developer's newer library cannot silently produce different tables.
const PinnedLibseccompVersion = "2.5.5"

// Version returns the version of the libseccomp linked into this binary, as
// libseccomp's own seccomp_version() reports it. It is (0, 0, 0) when the
// library cannot be queried, which the drift test treats as "libseccomp is not
// available here" rather than as version 0.0.0.
func Version() (uint, uint, uint) {
	return libseccomp.GetLibraryVersion()
}

// VersionString formats Version the way the generated file records it.
func VersionString() string {
	major, minor, micro := Version()
	return fmt.Sprintf("%d.%d.%d", major, minor, micro)
}

// CheckVersion reports whether got matches the expected version. The error it
// returns is the whole point of the check: it says which library was found,
// which one the tables are pinned to, and what to do about it.
func CheckVersion(expected, got string) error {
	if got == expected {
		return nil
	}
	return fmt.Errorf("libseccomp %s is linked here but the tables are pinned to %s: "+
		"refusing to generate, so a newer library cannot silently change the committed tables. "+
		"To regenerate for the installed library, bump PinnedLibseccompVersion in "+
		"internal/mkseccomptables/gen to %s and regenerate deliberately",
		got, expected, got)
}

// Result is one generation: the formatted Go source and what went into it.
type Result struct {
	// Source is the complete, gofmt'ed content of libseccomp_linux.go.
	Source []byte
	// Architectures are the SCMP_ARCH_* names the tables cover, sorted.
	Architectures []string
	// Version is the libseccomp version the source records, from
	// seccomp_version().
	Version string
}

// archPairs maps the generated table's SCMP_ARCH_* keys to libseccomp's own
// architecture tokens.
var archPairs = []struct {
	goName string
	scmp   libseccomp.ScmpArch
}{
	{"SCMP_ARCH_X86", libseccomp.ArchX86},
	{"SCMP_ARCH_X86_64", libseccomp.ArchAMD64},
	{"SCMP_ARCH_X32", libseccomp.ArchX32},
	{"SCMP_ARCH_ARM", libseccomp.ArchARM},
	{"SCMP_ARCH_AARCH64", libseccomp.ArchARM64},
	{"SCMP_ARCH_LOONGARCH64", libseccomp.ArchLOONGARCH64},
	{"SCMP_ARCH_MIPS", libseccomp.ArchMIPS},
	{"SCMP_ARCH_MIPS64", libseccomp.ArchMIPS64},
	{"SCMP_ARCH_MIPS64N32", libseccomp.ArchMIPS64N32},
	{"SCMP_ARCH_MIPSEL", libseccomp.ArchMIPSEL},
	{"SCMP_ARCH_MIPSEL64", libseccomp.ArchMIPSEL64},
	{"SCMP_ARCH_MIPSEL64N32", libseccomp.ArchMIPSEL64N32},
	{"SCMP_ARCH_PPC", libseccomp.ArchPPC},
	{"SCMP_ARCH_PPC64", libseccomp.ArchPPC64},
	{"SCMP_ARCH_PPC64LE", libseccomp.ArchPPC64LE},
	{"SCMP_ARCH_RISCV64", libseccomp.ArchRISCV64},
	{"SCMP_ARCH_S390", libseccomp.ArchS390},
	{"SCMP_ARCH_S390X", libseccomp.ArchS390X},
}

// The pseudo-syscall ranges libseccomp uses, from its syscalls.c: a number in
// the socket range is multiplexed through socketcall(2) with subcall = (-nr) %
// 100, one in the ipc range through ipc(2) with subcall = (-nr) % 200.
const (
	socketLow, socketHigh = -120, -100
	ipcLow, ipcHigh       = -224, -200

	// numberScanLimit is how far the number -> name enumeration walks. Most
	// libseccomp tables are a few hundred entries, but aarch64/arm carry the
	// ARM private syscalls at 0x0f0000 (983040), so the limit covers those.
	numberScanLimit = 1 << 20
)

// pseudoEntry is one generated libseccompPseudo value.
type pseudoEntry struct {
	mux     uint32
	subcall uint32
	flat    uint32
}

var entryRe = regexp.MustCompile(`^\t\t"([a-zA-Z0-9_]+)":\s+\d+,$`)

// Generate extracts the tables from the linked libseccomp and returns the
// formatted Go source. syscallsFile is the generated kernel-header tables
// (syscalls_linux.go), used only as a candidate list of names to try;
// expectedVersion pins the libseccomp the extraction is allowed to come from.
func Generate(syscallsFile, expectedVersion string) (*Result, error) {
	version := VersionString()
	if err := CheckVersion(expectedVersion, version); err != nil {
		return nil, err
	}
	major, minor, micro := Version()

	// The kernel-header tables are a candidate list for the name lookup, not
	// the result: libseccomp may resolve a name that is absent there, and may
	// fail to resolve one that is present.
	candidates, err := parseCandidateNames(syscallsFile)
	if err != nil {
		return nil, err
	}

	positive := map[string]map[string]uint32{}
	pseudo := map[string]map[string]pseudoEntry{}
	var archNames []string

	for _, p := range archPairs {
		// An architecture this libseccomp does not know fails to resolve even
		// "read"; skip it rather than emitting an empty table. (loongarch64 on
		// libseccomp <= 2.5.5 is the case here; the compiler falls back to the
		// kernel-header table for it.)
		if _, err := libseccomp.GetSyscallFromNameByArch("read", p.scmp); err != nil {
			fmt.Fprintf(os.Stderr, "mkseccomptables: skipping %s: %v\n", p.goName, err)
			continue
		}

		// The direct-wired number of every name libseccomp can name.
		flatByName := map[string]uint32{}
		localCandidates := map[string]bool{}
		for n := 0; n < numberScanLimit; n++ {
			name, err := libseccomp.ScmpSyscall(n).GetNameByArch(p.scmp)
			if err != nil || name == "" {
				continue
			}
			// Keep the largest number that names this syscall. The mips
			// family carries a fixed base offset (4000 and up), so a name
			// resolves both at its table index and at index+base; the number
			// the kernel and libseccomp's own rewrite use is the larger one.
			if n > int(flatByName[name]) {
				flatByName[name] = uint32(n)
			}
			localCandidates[name] = true
		}
		// The multiplexing pseudo-syscall names, which have no direct number on
		// architectures that spell them only as socketcall/ipc subcalls.
		for n := -1; n >= -400; n-- {
			name, err := libseccomp.ScmpSyscall(n).GetNameByArch(p.scmp)
			if err != nil || name == "" {
				continue
			}
			localCandidates[name] = true
		}

		muxSocketcall := resolvePositive(p.scmp, "socketcall")
		muxIPC := resolvePositive(p.scmp, "ipc")

		pos := map[string]uint32{}
		pse := map[string]pseudoEntry{}
		for name := range candidates {
			localCandidates[name] = true
		}
		for name := range localCandidates {
			nr, err := libseccomp.GetSyscallFromNameByArch(name, p.scmp)
			if err != nil {
				continue
			}
			switch {
			case nr >= 0:
				pos[name] = uint32(nr)
			case nr >= socketLow && nr <= socketHigh:
				if muxSocketcall == 0 {
					continue
				}
				pse[name] = pseudoEntry{
					mux:     muxSocketcall,
					subcall: uint32((-nr) % 100),
					flat:    flatByName[name],
				}
			case nr >= ipcLow && nr <= ipcHigh:
				if muxIPC == 0 {
					continue
				}
				pse[name] = pseudoEntry{
					mux:     muxIPC,
					subcall: uint32((-nr) % 200),
					flat:    flatByName[name],
				}
			}
			// Any other negative number is a name libseccomp has no rule
			// for: abi_rule_add() returns without adding anything, so the
			// name is deliberately absent from both tables.
		}
		if len(pos) == 0 {
			continue
		}
		positive[p.goName] = pos
		if len(pse) > 0 {
			pseudo[p.goName] = pse
		}
		archNames = append(archNames, p.goName)
	}
	sort.Strings(archNames)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, `//go:build linux

// Code generated by internal/mkseccomptables. DO NOT EDIT.
//
// Extracted from libseccomp %d.%d.%d through its public name-resolution API.
// See internal/mkseccomptables for how the numbers are derived and why they
// are generated from libseccomp rather than from the kernel headers.

package seccomp

// libseccompGeneratedVersion is the version of libseccomp whose syscall tables
// this file holds, as reported by seccomp_version(). The cgo-free compiler
// resolves names from these tables while the cgo build resolves them from the
// libseccomp it links against, so when the two differ a name the newer library
// knows is absent here and its rule is dropped -- for a deny rule, fail-open.
// TestGeneratedTablesMatchCommitted fails when this does not match the
// libseccomp on the build host and when the generated content differs from this
// file.
const libseccompGeneratedVersion = %q

// pseudoSyscall is one syscall name an architecture multiplexes through a
// multiplexor: libseccomp emits a rule on the multiplexor's number with
// argument 0 equal to subcall, and, when the architecture has a direct-wired
// number for the name, a second rule on that number.
type pseudoSyscall struct {
	// mux is the syscall number of the multiplexor (socketcall(2) or ipc(2)).
	mux uint32
	// subcall is the value argument 0 must equal to select the subcall.
	subcall uint32
	// flat is the direct-wired syscall number for the same name, or 0 when
	// the architecture has none and only the multiplexed rule exists.
	flat uint32
}

// libseccompSyscalls maps a SCMP_ARCH_* name to the syscall names libseccomp
// resolves to a non-negative number on that architecture. A name absent here
// and from libseccompPseudo is one libseccomp cannot resolve, or resolves to a
// pseudo number it adds no rule for; the cgo-free compiler drops it either way.
var libseccompSyscalls = map[string]map[string]uint32{
`, major, minor, micro, version)

	for _, arch := range archNames {
		table := positive[arch]
		names := make([]string, 0, len(table))
		for name := range table {
			names = append(names, name)
		}
		sort.Strings(names)

		fmt.Fprintf(&buf, "\t%q: {\n", arch)
		for _, name := range names {
			fmt.Fprintf(&buf, "\t\t%q: %d,\n", name, table[name])
		}
		fmt.Fprintf(&buf, "\t},\n")
	}
	fmt.Fprintf(&buf, "}\n")

	fmt.Fprintf(&buf, `
// libseccompPseudo maps a SCMP_ARCH_* name to the syscall names it multiplexes
// through socketcall(2) or ipc(2). An architecture with no entry has no
// multiplexor, and every name in libseccompSyscalls for it is filtered
// directly.
var libseccompPseudo = map[string]map[string]pseudoSyscall{
`)
	for _, arch := range archNames {
		table, ok := pseudo[arch]
		if !ok {
			continue
		}
		names := make([]string, 0, len(table))
		for name := range table {
			names = append(names, name)
		}
		sort.Strings(names)

		fmt.Fprintf(&buf, "\t%q: {\n", arch)
		for _, name := range names {
			e := table[name]
			fmt.Fprintf(&buf, "\t\t%q: {mux: %d, subcall: %d, flat: %d},\n", name, e.mux, e.subcall, e.flat)
		}
		fmt.Fprintf(&buf, "\t},\n")
	}
	fmt.Fprintf(&buf, "}\n")

	src, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("formatting generated source: %w", err)
	}
	return &Result{Source: src, Architectures: archNames, Version: version}, nil
}

// resolvePositive resolves a name and returns its number when it is
// non-negative, and 0 otherwise. It is how the multiplexor's own number is
// found: on a multiplexing architecture socketcall(2)/ipc(2) are ordinary
// positive syscalls.
func resolvePositive(arch libseccomp.ScmpArch, name string) uint32 {
	nr, err := libseccomp.GetSyscallFromNameByArch(name, arch)
	if err != nil || nr < 0 {
		return 0
	}
	return uint32(nr)
}

// parseCandidateNames reads the names of the generated kernel-header tables
// out of syscalls_linux.go and returns their union. The file is generated and
// its shape is fixed, so a regex is enough.
func parseCandidateNames(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	names := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if m := entryRe.FindStringSubmatch(sc.Text()); m != nil {
			names[m[1]] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: no names parsed; is it the generated file?", path)
	}
	return names, nil
}
