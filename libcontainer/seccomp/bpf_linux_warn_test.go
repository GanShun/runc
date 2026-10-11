//go:build linux

package seccomp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// TestUnresolvableSyscallWarnsAndDropsNothing pins the visibility half of the
// version-skew guard.
//
// A profile that names a syscall the name table cannot resolve has that rule
// dropped, on both builds: libseccomp's abi_rule_add() adds nothing for a name
// it cannot resolve, and the cgo-free compiler matches that so the two filters
// stay the same. For a *deny* rule the drop is fail-open -- the filter does not
// enforce what the profile says -- and it used to be reported only at debug
// level, which is invisible in a normal run. It is now a warning naming the
// syscall.
//
// The second half of the test is that the warning is the whole change: making
// the drop visible must not alter what gets filtered. The compiled program with
// the unresolvable rule is required to be identical to the one without it,
// which is what "the rule is dropped" means at the instruction level.
func TestUnresolvableSyscallWarnsAndDropsNothing(t *testing.T) {
	const unknown = "not_a_real_syscall_name"

	// A default the unknown rule does not share, so the rule reaches the name
	// lookup rather than being skipped earlier as redundant with the default.
	base := func() *configs.Seccomp {
		return &configs.Seccomp{
			DefaultAction: configs.Errno,
			Syscalls: []*configs.Syscall{
				{Name: "clone", Action: configs.Allow},
			},
		}
	}
	withUnknown := base()
	withUnknown.Syscalls = append(withUnknown.Syscalls,
		&configs.Syscall{Name: unknown, Action: configs.Allow})

	want, err := compileFilter(base())
	if err != nil {
		t.Fatalf("compileFilter (without the unresolvable rule): %v", err)
	}

	var logs bytes.Buffer
	prevOut, prevLevel := logrus.StandardLogger().Out, logrus.GetLevel()
	logrus.SetOutput(&logs)
	logrus.SetLevel(logrus.WarnLevel)
	defer func() {
		logrus.SetOutput(prevOut)
		logrus.SetLevel(prevLevel)
	}()

	got, err := compileFilter(withUnknown)
	if err != nil {
		t.Fatalf("compileFilter (with the unresolvable rule): %v", err)
	}

	if !strings.Contains(logs.String(), unknown) {
		t.Errorf("dropping the rule for %q produced no warning naming it; log output:\n%s",
			unknown, logs.String())
	}
	t.Logf("warning emitted: %s", strings.TrimSpace(logs.String()))

	if len(got) != len(want) {
		t.Fatalf("the unresolvable rule changed the filter: %d instructions with it, %d without",
			len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the unresolvable rule changed instruction %d: got %v, want %v",
				i, got[i], want[i])
		}
	}
}
