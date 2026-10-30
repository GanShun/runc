//go:build linux && cgo

// Package archmap holds the one mapping from the generated seccomp table's
// SCMP_ARCH_* keys to libseccomp's own architecture tokens.
//
// It exists because two cgo-only tools need the same list and must not drift:
// internal/mkseccomptables/gen enumerates libseccomp's syscall tables through
// it, and vmdiff/namecov compares the committed kernel-header tables against
// libseccomp through it. An architecture added to one list but not the other
// would silently change what gets generated or reported.
package archmap

import libseccomp "github.com/seccomp/libseccomp-golang"

// Pair is one SCMP_ARCH_* key and the libseccomp architecture it names.
type Pair struct {
	GoName string
	Scmp   libseccomp.ScmpArch
}

// Pairs is every architecture the generated table covers.
var Pairs = []Pair{
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
