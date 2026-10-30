//go:build linux

package seccomp

import (
	"golang.org/x/sys/unix"
)

// seccompArch carries everything the compiler needs to know about one seccomp
// architecture, so there is one place to add one. It used to be five parallel
// maps keyed by the same SCMP_ARCH_* string -- auditArch, archIs32Bit and
// archLittleEndian here, archs in config.go, and the generated
// goarchToSeccompArch -- and an architecture added to one but not another was a
// silent disagreement rather than a compile error.
type seccompArch struct {
	// audit is the AUDIT_ARCH_* value the kernel reports in
	// seccomp_data.arch. x32 shares x86_64's.
	audit uint32
	// is32 is whether argument comparisons use only the low 32 bits, which is
	// what libseccomp does when its arch definition has ARCH_SIZE_32. It
	// cannot be read off audit: x32 shares x86_64's value and is 32-bit, and
	// the two mips n32 ABIs set the 64-bit bit in their own.
	is32 bool
	// littleEndian is the byte order. libseccomp refuses (EDOM) to add an
	// architecture whose byte order differs from the native one, and the
	// compiler refuses the same ones.
	littleEndian bool
	// oci is the short name OCI profiles use, which is what
	// configs.Seccomp.Architectures carries and what ConvertStringToArch
	// returns.
	oci string
	// goarch is runtime.GOARCH for the architectures Go can be built for, and
	// empty for the ones it cannot (x32, the mips n32 ABIs, 31-bit s390).
	goarch string
}

// seccompArches is the single architecture table. The SCMP_ARCH_* key is the
// name the compiler's sections and the generated syscall tables are keyed by.
var seccompArches = map[string]seccompArch{
	"SCMP_ARCH_X86":         {audit: unix.AUDIT_ARCH_I386, is32: true, littleEndian: true, oci: "x86", goarch: "386"},
	"SCMP_ARCH_X86_64":      {audit: unix.AUDIT_ARCH_X86_64, littleEndian: true, oci: "amd64", goarch: "amd64"},
	"SCMP_ARCH_X32":         {audit: unix.AUDIT_ARCH_X86_64, is32: true, littleEndian: true, oci: "x32"},
	"SCMP_ARCH_ARM":         {audit: unix.AUDIT_ARCH_ARM, is32: true, littleEndian: true, oci: "arm", goarch: "arm"},
	"SCMP_ARCH_AARCH64":     {audit: unix.AUDIT_ARCH_AARCH64, littleEndian: true, oci: "arm64", goarch: "arm64"},
	"SCMP_ARCH_LOONGARCH64": {audit: unix.AUDIT_ARCH_LOONGARCH64, littleEndian: true, oci: "loong64", goarch: "loong64"},
	"SCMP_ARCH_MIPS":        {audit: unix.AUDIT_ARCH_MIPS, is32: true, oci: "mips", goarch: "mips"},
	"SCMP_ARCH_MIPS64":      {audit: unix.AUDIT_ARCH_MIPS64, oci: "mips64", goarch: "mips64"},
	"SCMP_ARCH_MIPS64N32":   {audit: unix.AUDIT_ARCH_MIPS64N32, is32: true, oci: "mips64n32"},
	"SCMP_ARCH_MIPSEL":      {audit: unix.AUDIT_ARCH_MIPSEL, is32: true, littleEndian: true, oci: "mipsel", goarch: "mipsle"},
	"SCMP_ARCH_MIPSEL64":    {audit: unix.AUDIT_ARCH_MIPSEL64, littleEndian: true, oci: "mipsel64", goarch: "mips64le"},
	"SCMP_ARCH_MIPSEL64N32": {audit: unix.AUDIT_ARCH_MIPSEL64N32, is32: true, littleEndian: true, oci: "mipsel64n32"},
	"SCMP_ARCH_PPC":         {audit: unix.AUDIT_ARCH_PPC, is32: true, oci: "ppc", goarch: "ppc"},
	"SCMP_ARCH_PPC64":       {audit: unix.AUDIT_ARCH_PPC64, oci: "ppc64", goarch: "ppc64"},
	"SCMP_ARCH_PPC64LE":     {audit: unix.AUDIT_ARCH_PPC64LE, littleEndian: true, oci: "ppc64le", goarch: "ppc64le"},
	"SCMP_ARCH_RISCV64":     {audit: unix.AUDIT_ARCH_RISCV64, littleEndian: true, oci: "riscv64", goarch: "riscv64"},
	"SCMP_ARCH_S390":        {audit: unix.AUDIT_ARCH_S390, is32: true, oci: "s390"},
	"SCMP_ARCH_S390X":       {audit: unix.AUDIT_ARCH_S390X, oci: "s390x", goarch: "s390x"},
}

// init fills config.go's arch-name views from the one table, so the two
// exported helpers have no separate list to maintain.
func init() {
	archShortNames = make(map[string]string, len(seccompArches))
	for scmp, a := range seccompArches {
		archShortNames[scmp] = a.oci
	}
}
