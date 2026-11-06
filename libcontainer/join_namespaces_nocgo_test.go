//go:build linux && !cgo

package libcontainer

import (
	"strings"
	"testing"
)

// TestJoinNamespacesRefuses covers the namespace types this build cannot join.
// Each is refused before any descriptor is opened, so this needs no privileges.
func TestJoinNamespacesRefuses(t *testing.T) {
	for _, tc := range []struct {
		it    initType
		entry string
		want  string
	}{
		// thread_group_empty: a Go process never is.
		{initStandard, "user:/proc/1/ns/user", "not supported without cgo"},
		// current_is_single_threaded: same, and nsexec can only because the C
		// constructor runs before the runtime starts.
		{initStandard, "time:/proc/1/ns/time", "not supported without cgo"},
		// An init gets a PID namespace by clone(2), not by setns(2).
		{initStandard, "pid:/proc/1/ns/pid", "not supported without cgo"},
		// Reaching this would leave the process in the host's PID namespace,
		// which is never what the caller asked for.
		{initSetns, "pid:/proc/1/ns/pid", "was not staged"},
	} {
		err := joinNamespaces(tc.it, []string{tc.entry})
		if err == nil {
			t.Errorf("%s: joined, want refusal", tc.entry)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %q, want it to mention %q", tc.entry, err, tc.want)
		}
		// Refused before any join: the kernel's own error for these
		// ("operation not permitted", "too many users") does not say why.
		if strings.Contains(err.Error(), "setns into") {
			t.Errorf("%s: reached setns(2), want a refusal first: %v", tc.entry, err)
		}
	}
}
