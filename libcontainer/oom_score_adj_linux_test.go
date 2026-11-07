package libcontainer

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func readOomScoreAdj(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		t.Fatalf("reading oom_score_adj: %v", err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parsing oom_score_adj %q: %v", data, err)
	}
	return value
}

// TestApplyOomScoreAdjWithoutCgo writes to this process's own file, which is the
// same one the container's init is given by pid, so it exercises the write and
// not only the formatting. The value is restored afterwards either way.
func TestApplyOomScoreAdjWithoutCgo(t *testing.T) {
	if !puregoNamespaces {
		t.Skip("only the cgo-free build writes oom_score_adj from the parent")
	}
	original := readOomScoreAdj(t)
	defer func() {
		restore := original
		if err := applyOomScoreAdj(os.Getpid(), &restore); err != nil {
			t.Fatalf("restoring oom_score_adj to %d: %v", original, err)
		}
	}()

	// Not original+1 blindly: 1000 is the maximum, it is what kubelet gives a
	// BestEffort pod, and a CI runner in one would make this test fail on a value
	// the kernel refuses rather than on the write it is checking. Lowering needs
	// CAP_SYS_RESOURCE below oom_score_adj_min, so a non-root run skips instead of
	// failing: the write is the code path, not the privilege to use it.
	want := original + 1
	if original >= 1000 {
		want = original - 1
	}
	if err := applyOomScoreAdj(os.Getpid(), &want); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("cannot lower oom_score_adj %d from %d without CAP_SYS_RESOURCE: %v", want, original, err)
		}
		t.Fatalf("applyOomScoreAdj(%d): %v", want, err)
	}
	if got := readOomScoreAdj(t); got != want {
		t.Errorf("oom_score_adj = %d, want %d", got, want)
	}
}

// TestApplyOomScoreAdjRefusesWhatTheKernelRefuses is the point of the change: a
// value the kernel rejects must be an error, not a silent no-op that leaves the
// container with the inherited score.
func TestApplyOomScoreAdjRefusesWhatTheKernelRefuses(t *testing.T) {
	if !puregoNamespaces {
		t.Skip("only the cgo-free build writes oom_score_adj from the parent")
	}
	outOfRange := 2000
	err := applyOomScoreAdj(os.Getpid(), &outOfRange)
	if err == nil {
		t.Fatal("applyOomScoreAdj accepted 2000, want the kernel's EINVAL")
	}
	if !strings.Contains(err.Error(), "oom_score_adj") {
		t.Errorf("error = %v, want it to name the field", err)
	}
}

// TestApplyOomScoreAdjLeavesAnUnsetValueAlone stops an unset field from being
// turned into a write of 0, which would override an inherited score.
func TestApplyOomScoreAdjLeavesAnUnsetValueAlone(t *testing.T) {
	original := readOomScoreAdj(t)
	if err := applyOomScoreAdj(os.Getpid(), nil); err != nil {
		t.Fatalf("applyOomScoreAdj(nil): %v", err)
	}
	if got := readOomScoreAdj(t); got != original {
		t.Errorf("oom_score_adj = %d, want it untouched at %d", got, original)
	}
}
