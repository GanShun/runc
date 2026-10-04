//go:build linux

package seccomp

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// This is a port of the -ENOSYS stub from the libseccomp build (see
// patchbpf/enosys_linux.go) to the cgo-free one. The stub is prepended to the
// compiled filter; it makes a syscall whose number is larger than any the
// profile mentions return ENOSYS instead of the profile's default action.
//
// That matters because libc probes for newer syscalls -- clone3, most visibly
// -- and needs ENOSYS to fall back to the older one (clone). With the default
// action being an errno, the fallback never happens and the program fails.

// retErrnoEnosys is SECCOMP_RET_ERRNO with ENOSYS.
var retErrnoEnosys = retErrno | uint32(unix.ENOSYS)&retDataMask

// s390(x) multiplexes syscalls numbered above 255 through setup(2). A syscall
// number the kernel does not know is left as 0 by that scheme, which would
// otherwise be given the default action, so the stub returns ENOSYS for it.
const s390xMultiplexSyscall = 0

// lastSyscallMap is keyed by AUDIT_ARCH and then by seccomp architecture name:
// x86_64 and x32 share one AUDIT_ARCH value but have their own syscall tables,
// and so need their own maxima.
type lastSyscallMap map[uint32]map[string]uint32

// isAllowAction reports whether an action is permissive enough that an unknown
// syscall should not be turned into ENOSYS. Trace counts as permissive: a
// tracer is expected to handle ENOSYS itself, and taking that decision away
// hurts emulation.
func isAllowAction(action configs.Action) bool {
	switch action {
	case configs.Allow, configs.Log, configs.Trace:
		return true
	default:
		return false
	}
}

// enosysStub returns the stub to prepend, or nil when the profile does not
// want one, following the same rules as the libseccomp build.
func enosysStub(config *configs.Seccomp) ([]bpf.Instruction, error) {
	if config.DefaultErrnoRet != nil && *config.DefaultErrnoRet == uint(retErrnoEnosys) {
		return nil, nil
	}
	if isAllowAction(config.DefaultAction) {
		logrus.Debugf("seccomp: skipping -ENOSYS stub filter generation")
		return nil, nil
	}
	lastSyscalls, err := findLastSyscalls(config)
	if err != nil {
		return nil, fmt.Errorf("error finding last syscalls for -ENOSYS stub: %w", err)
	}
	if len(lastSyscalls) == 0 {
		// Nothing to guard: there is no "past the end of the table" to
		// detect. Upstream still emits a do-nothing stub here.
		return nil, nil
	}
	return generateEnosysStub(lastSyscalls)
}

// findLastSyscalls finds, per architecture, the largest syscall number the
// profile mentions.
func findLastSyscalls(config *configs.Seccomp) (lastSyscallMap, error) {
	arches := make(map[string]struct{})
	for _, ociArch := range config.Architectures {
		if _, ok := auditArch[ociArch]; !ok {
			return nil, fmt.Errorf("unknown seccomp architecture %q", ociArch)
		}
		arches[ociArch] = struct{}{}
	}
	// Some profiles leave the native architecture out of the list, which
	// would make the stub a no-op, so always include it.
	native, err := nativeSeccompArch()
	if err != nil {
		return nil, err
	}
	if _, ok := arches[native]; !ok {
		logrus.Debugf("seccomp: adding implied native architecture %v to config set", native)
		arches[native] = struct{}{}
	}

	last := make(lastSyscallMap)
	for arch := range arches {
		audit := auditArch[arch]
		table, ok := syscallNumbers[arch]
		if !ok {
			// x/sys/unix carries no table for x32 (or for 31-bit s390).
			// Such an architecture gets no -ENOSYS check, which means its
			// syscalls fall through to the filter and take its default
			// action. That is fail-closed, and x32 is rare enough to leave
			// for now; the cgo build handles it through libseccomp.
			logrus.Debugf("seccomp: no syscall table for %v, skipping its -ENOSYS check", arch)
			continue
		}

		var max uint32
		for _, rule := range config.Syscalls {
			if rule == nil {
				continue
			}
			num, ok := table[rule.Name]
			if !ok {
				// A name this architecture does not have is ignored, as
				// elsewhere.
				continue
			}
			if num > max {
				max = num
			}
		}
		if max == 0 {
			logrus.Warnf("could not find any syscalls for arch %v", arch)
			continue
		}
		logrus.Debugf("seccomp: largest syscall number for arch %v is %v", arch, max)
		if last[audit] == nil {
			last[audit] = map[string]uint32{}
		}
		last[audit][arch] = max
	}
	return last, nil
}

// generateEnosysStub builds the stub. Sections are generated in reverse
// (prepended to the tail) because the jumps are measured from the end of the
// program, so that they stay valid once the stub is prepended to the filter.
func generateEnosysStub(lastSyscalls lastSyscallMap) ([]bpf.Instruction, error) {
	// A jump table per audit architecture, measured from the end of the
	// program for the same reason.
	archJumpTable := map[uint32]uint32{}

	programTail := []bpf.Instruction{
		// Sections that fall through jump into the filter.
		bpf.Jump{Skip: 1},
		// Sections that give up land here.
		bpf.RetConstant{Val: retErrnoEnosys},
	}

	for auditArch, maxSyscalls := range lastSyscalls {
		baseJumpEnosys := uint32(len(programTail) - 1)
		baseJumpFilter := baseJumpEnosys + 1

		section := []bpf.Instruction{
			// Jumped to directly by the architecture dispatch, so the
			// syscall number has to be loaded here.
			bpf.LoadAbsolute{Off: seccompDataNr, Size: 4},
		}

		switch len(maxSyscalls) {
		case 0:
			continue
		case 1:
			var (
				arch  string
				sysno uint32
			)
			for a, no := range maxSyscalls {
				arch, sysno = a, no
			}

			if arch == "SCMP_ARCH_S390" || arch == "SCMP_ARCH_S390X" {
				section = append(section,
					bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: s390xMultiplexSyscall, SkipTrue: 1},
					bpf.RetConstant{Val: retErrnoEnosys},
				)
			}

			var sectionTail []bpf.Instruction
			if baseJumpEnosys+1 <= 255 {
				sectionTail = []bpf.Instruction{
					// nr > max -> ENOSYS
					bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: sysno, SkipTrue: uint8(baseJumpEnosys + 1)},
					bpf.Jump{Skip: baseJumpFilter},
				}
			} else {
				sectionTail = []bpf.Instruction{
					// nr <= max -> into the filter
					bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: sysno, SkipTrue: 1},
					bpf.RetConstant{Val: retErrnoEnosys},
					bpf.Jump{Skip: baseJumpFilter},
				}
			}

			// On x86_64 the ABI is signalled by bit 30 of the syscall
			// number, so the wrong mode has to skip this section.
			if auditArch == unix.AUDIT_ARCH_X86_64 {
				switch arch {
				case "SCMP_ARCH_X86_64":
					// An x32 syscall must not be compared against the
					// x86_64 maximum.
					sectionTail = append([]bpf.Instruction{
						bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1 << 30, SkipTrue: uint8(len(sectionTail) - 1)},
					}, sectionTail...)
				case "SCMP_ARCH_X32":
					sectionTail = append([]bpf.Instruction{
						bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: 1 << 30, SkipTrue: uint8(len(sectionTail) - 1)},
					}, sectionTail...)
				default:
					return nil, fmt.Errorf("unknown amd64 native architecture %v", arch)
				}
			}
			section = append(section, sectionTail...)
		case 2:
			// x32 and x86_64 are the only architectures that share an
			// AUDIT_ARCH value, so this case is that pair.
			if auditArch != unix.AUDIT_ARCH_X86_64 {
				return nil, fmt.Errorf("unknown architecture overlap on native arch %#x", auditArch)
			}
			x32sysno, ok := maxSyscalls["SCMP_ARCH_X32"]
			if !ok {
				return nil, fmt.Errorf("missing SCMP_ARCH_X32 in overlapping x86_64 arch: %v", maxSyscalls)
			}
			x86sysno, ok := maxSyscalls["SCMP_ARCH_X86_64"]
			if !ok {
				return nil, fmt.Errorf("missing SCMP_ARCH_X86_64 in overlapping x86_64 arch: %v", maxSyscalls)
			}

			if baseJumpEnosys+2 <= 255 {
				section = append(section,
					bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1 << 30, SkipTrue: 1},
					bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: x86sysno, SkipTrue: uint8(baseJumpEnosys + 2), SkipFalse: 1},
					bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: x32sysno, SkipTrue: uint8(baseJumpEnosys + 1)},
					bpf.Jump{Skip: baseJumpFilter},
				)
			} else {
				section = append(section,
					bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 1 << 30, SkipTrue: 1},
					bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: x86sysno, SkipTrue: 1, SkipFalse: 2},
					bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: x32sysno, SkipTrue: 1},
					bpf.RetConstant{Val: retErrnoEnosys},
					bpf.Jump{Skip: baseJumpFilter},
				)
			}
		default:
			return nil, fmt.Errorf("invalid number of architecture overlaps: %v", len(maxSyscalls))
		}

		programTail = append(section, programTail...)
		archJumpTable[auditArch] = uint32(len(programTail))
	}

	// Architectures that appear in neither table fall through to the filter;
	// the filter's own bad-architecture action deals with them.
	programTail = append([]bpf.Instruction{
		bpf.Jump{Skip: uint32(len(programTail))},
	}, programTail...)

	for auditArch := range lastSyscalls {
		jump := uint32(len(programTail)) - archJumpTable[auditArch]
		if jump <= 255 {
			programTail = append([]bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: auditArch, SkipTrue: uint8(jump)},
			}, programTail...)
		} else {
			programTail = append([]bpf.Instruction{
				bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: auditArch, SkipTrue: 1},
				bpf.Jump{Skip: jump},
			}, programTail...)
		}
	}

	programTail = append([]bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompDataArch, Size: 4},
	}, programTail...)

	return programTail, nil
}
