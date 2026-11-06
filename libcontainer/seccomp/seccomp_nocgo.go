//go:build linux && !cgo

package seccomp

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// This is the cgo-free implementation: the profile is compiled to classic BPF
// in Go (bpf_linux.go) instead of being handed to libseccomp, and installed
// with seccomp(2).
//
// Both behaviours of the libseccomp build are reproduced. The -ENOSYS stub that
// runc prepends -- so that syscalls the profile knows nothing about return
// ENOSYS rather than the default action, which is what lets libc fall back from
// newer syscalls (clone3) to older ones (clone) -- is in bpf_enosys_linux.go.
// And the rules are a balanced binary search over the syscall number rather than
// a linear chain, so a syscall costs O(log rules) comparisons. The numbers come
// from internal/mksyscalls rather than being maintained by hand.

// InitSeccomp installs the seccomp filters to be used in the container as
// specified in config.
// Returns the seccomp file descriptor if any of the filters include a
// SCMP_ACT_NOTIFY action, otherwise returns -1.
func InitSeccomp(config *configs.Seccomp) (int, error) {
	if config == nil {
		return -1, errors.New("cannot initialize Seccomp - nil config passed")
	}

	prog, err := compileFilter(config)
	if err != nil {
		return -1, err
	}
	filter, err := assembleFilterProgram(prog)
	if err != nil {
		return -1, err
	}
	flags, err := filterFlags(config)
	if err != nil {
		return -1, err
	}
	return loadFilter(flags, filter)
}

// assembleFilterProgram turns the compiled program into the form seccomp(2)
// takes.
func assembleFilterProgram(prog []bpf.Instruction) ([]unix.SockFilter, error) {
	raw, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("error assembling seccomp filter: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("compiled seccomp filter is empty")
	}
	filter := make([]unix.SockFilter, 0, len(raw))
	for _, insn := range raw {
		filter = append(filter, unix.SockFilter{
			Code: insn.Op,
			Jt:   insn.Jt,
			Jf:   insn.Jf,
			K:    insn.K,
		})
	}
	return filter, nil
}

// filterFlags converts the profile's flags into SECCOMP_FILTER_FLAG_* bits.
func filterFlags(config *configs.Seccomp) (uint, error) {
	var flags uint
	for _, flag := range config.Flags {
		switch flag {
		case flagTsync:
			// Map the profile's explicit request to the kernel flag. The cgo
			// build does not: its setFlag treats tsync as a no-op on the belief
			// that libseccomp-golang's filter always syncs, but runc exports
			// the BPF and loads it through patchbpf, and that path never sets
			// SECCOMP_FILTER_FLAG_TSYNC. So the two builds agree when the
			// profile does not ask -- neither syncs, and a filter installed
			// with prctl(2) covers the calling thread only -- and this build is
			// the one that honours an explicit request. A multi-threaded
			// installer needs the flag to have every thread filtered.
			// TestFilterSyncsOnlyWhenAsked (seccomp_nocgo_tsync_test.go) pins
			// this against the kernel.
			flags |= unix.SECCOMP_FILTER_FLAG_TSYNC
		case specs.LinuxSeccompFlagLog:
			flags |= unix.SECCOMP_FILTER_FLAG_LOG
		case specs.LinuxSeccompFlagSpecAllow:
			flags |= unix.SECCOMP_FILTER_FLAG_SPEC_ALLOW
		case specs.LinuxSeccompFlagWaitKillableRecv:
			flags |= unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
		default:
			return 0, &unknownFlagError{flag: flag}
		}
	}

	for _, call := range config.Syscalls {
		if call != nil && call.Action == configs.Notify {
			flags |= unix.SECCOMP_FILTER_FLAG_NEW_LISTENER
			break
		}
	}

	// TSYNC and NEW_LISTENER both return a value -- a thread id and a descriptor
	// -- and seccomp_set_mode_filter refuses the pair with EINVAL unless
	// TSYNC_ESRCH says the caller can tell them apart. It also changes a failed
	// synchronisation from a positive tid, which a caller checking only errno
	// reads as success, into a negative errno.
	if flags&unix.SECCOMP_FILTER_FLAG_TSYNC != 0 {
		flags |= unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH
	}
	return flags, nil
}

// loadFilter installs filter on the current process with seccomp(2), falling
// back to prctl(2) when no flags are needed, as the kernel interface requires.
func loadFilter(flags uint, filter []unix.SockFilter) (int, error) {
	fprog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if flags == 0 {
		err := unix.Prctl(unix.PR_SET_SECCOMP,
			unix.SECCOMP_MODE_FILTER,
			uintptr(unsafe.Pointer(&fprog)), 0, 0)
		if err != nil {
			return -1, fmt.Errorf("error loading seccomp filter: %w", err)
		}
		runtime.KeepAlive(filter)
		runtime.KeepAlive(fprog)
		return -1, nil
	}

	ret, errno := seccompSetModeFilter(flags, &fprog)
	// Kernels before 5.7 do not know TSYNC_ESRCH and reject the call outright.
	// Without a listener the original call is still worth retrying: a failed
	// synchronisation then shows up as a positive tid, which
	// seccompFilterResult turns back into an error.
	if errno == unix.EINVAL && flags&unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0 &&
		flags&unix.SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 {
		flags &^= unix.SECCOMP_FILTER_FLAG_TSYNC_ESRCH
		ret, errno = seccompSetModeFilter(flags, &fprog)
	}
	if errno != 0 {
		return -1, fmt.Errorf("error loading seccomp filter: %w", errno)
	}

	fd, err := seccompFilterResult(flags, ret)
	if err != nil {
		return -1, fmt.Errorf("error loading seccomp filter: %w", err)
	}
	runtime.KeepAlive(filter)
	runtime.KeepAlive(fprog)
	return fd, nil
}

// seccompSetModeFilter is the seccomp(2) call itself, kept apart so that
// loadFilter can retry it with a different flag set.
func seccompSetModeFilter(flags uint, fprog *unix.SockFprog) (uintptr, unix.Errno) {
	ret, _, errno := unix.RawSyscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(flags),
		uintptr(unsafe.Pointer(fprog)))
	return ret, errno
}

// seccompFilterResult interprets what seccomp(2) returned.
//
// With NEW_LISTENER the value is the notification descriptor. Otherwise the call
// returns 0, or -- when TSYNC is set and the kernel has no TSYNC_ESRCH to report
// failures through -- the tid of a thread it could not filter: a positive value
// with errno 0, because the kernel does not consider it an error. Reading only
// errno there reports success while that thread runs unfiltered, which is the
// opposite of what a profile asking for tsync is for.
func seccompFilterResult(flags uint, ret uintptr) (fd int, err error) {
	if flags&unix.SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 {
		return int(ret), nil
	}
	if flags&unix.SECCOMP_FILTER_FLAG_TSYNC != 0 && ret != 0 {
		return -1, fmt.Errorf("filter was not applied to thread %d: %w", int64(ret), unix.ESRCH)
	}
	return -1, nil
}

// FlagSupported checks if the flag is known to runc. Unlike the libseccomp
// build there is nothing to probe: the kernel rejects a flag it does not
// understand when the filter is loaded, and seccomp(2) is the only interface
// available without libseccomp.
func FlagSupported(flag specs.LinuxSeccompFlag) error {
	switch flag {
	case flagTsync,
		specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv:
		return nil
	}
	return &unknownFlagError{flag: flag}
}

// Version returns major, minor, and micro. There is no libseccomp in this
// build, so there is no version to report.
func Version() (uint, uint, uint) {
	return 0, 0, 0
}

// Enabled is true if seccomp support is compiled in.
const Enabled = true
