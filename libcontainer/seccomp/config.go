package seccomp

import (
	"fmt"
	"maps"
	"slices"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// flagTsync is recognized but ignored by runc, and it is not defined
// in the runtime-spec.
const flagTsync = "SECCOMP_FILTER_FLAG_TSYNC"

var operators = map[string]configs.Operator{
	"SCMP_CMP_NE":        configs.NotEqualTo,
	"SCMP_CMP_LT":        configs.LessThan,
	"SCMP_CMP_LE":        configs.LessThanOrEqualTo,
	"SCMP_CMP_EQ":        configs.EqualTo,
	"SCMP_CMP_GE":        configs.GreaterThanOrEqualTo,
	"SCMP_CMP_GT":        configs.GreaterThan,
	"SCMP_CMP_MASKED_EQ": configs.MaskEqualTo,
}

// KnownOperators returns the list of the known operations.
// Used by `runc features`.
func KnownOperators() []string {
	return slices.Sorted(maps.Keys(operators))
}

var actions = map[string]configs.Action{
	"SCMP_ACT_KILL":         configs.Kill,
	"SCMP_ACT_ERRNO":        configs.Errno,
	"SCMP_ACT_TRAP":         configs.Trap,
	"SCMP_ACT_ALLOW":        configs.Allow,
	"SCMP_ACT_TRACE":        configs.Trace,
	"SCMP_ACT_LOG":          configs.Log,
	"SCMP_ACT_NOTIFY":       configs.Notify,
	"SCMP_ACT_KILL_THREAD":  configs.KillThread,
	"SCMP_ACT_KILL_PROCESS": configs.KillProcess,
}

// KnownActions returns the list of the known actions.
// Used by `runc features`.
func KnownActions() []string {
	return slices.Sorted(maps.Keys(actions))
}

// archShortNames maps an SCMP_ARCH_* name to the short name OCI profiles use.
// It is a derived view of seccompArches, the single architecture table, filled
// by init() in arch_linux.go. On a build without that table it is empty and the
// arch-name helpers report nothing, which matches this package having no
// compiler there either.
var archShortNames map[string]string

// KnownArchs returns the list of the known archs.
// Used by `runc features`.
func KnownArchs() []string {
	return slices.Sorted(maps.Keys(archShortNames))
}

// ConvertStringToOperator converts a string into a Seccomp comparison operator.
// Comparison operators use the names they are assigned by Libseccomp's header.
// Attempting to convert a string that is not a valid operator results in an
// error.
func ConvertStringToOperator(in string) (configs.Operator, error) {
	if op, ok := operators[in]; ok {
		return op, nil
	}
	return 0, fmt.Errorf("string %s is not a valid operator for seccomp", in)
}

// ConvertStringToAction converts a string into a Seccomp rule match action.
// Actions use the names they are assigned in Libseccomp's header.
// Attempting to convert a string that is not a valid action results in an
// error.
func ConvertStringToAction(in string) (configs.Action, error) {
	if act, ok := actions[in]; ok {
		return act, nil
	}
	return 0, fmt.Errorf("string %s is not a valid action for seccomp", in)
}

// ConvertStringToArch converts a string into a Seccomp comparison arch.
func ConvertStringToArch(in string) (string, error) {
	if arch, ok := archShortNames[in]; ok {
		return arch, nil
	}
	return "", fmt.Errorf("string %s is not a valid arch for seccomp", in)
}

// List of flags known to this version of runc.
var flags = []string{
	flagTsync,
	string(specs.LinuxSeccompFlagSpecAllow),
	string(specs.LinuxSeccompFlagLog),
	string(specs.LinuxSeccompFlagWaitKillableRecv),
}

// KnownFlags returns the list of the known filter flags.
// Used by `runc features`.
func KnownFlags() []string {
	return flags
}

// SupportedFlags returns the list of the supported filter flags.
// This list may be a subset of one returned by KnownFlags due to
// some flags not supported by the current kernel and/or libseccomp.
// Used by `runc features`.
func SupportedFlags() []string {
	if !Enabled {
		return nil
	}

	var res []string
	for _, flag := range flags {
		if FlagSupported(specs.LinuxSeccompFlag(flag)) == nil {
			res = append(res, flag)
		}
	}

	return res
}

// unknownFlagError is returned for a flag runc does not know about. It is
// shared by the libseccomp and the cgo-free builds.
type unknownFlagError struct {
	flag specs.LinuxSeccompFlag
}

func (e *unknownFlagError) Error() string {
	return "seccomp flag " + string(e.flag) + " is not known to runc"
}
