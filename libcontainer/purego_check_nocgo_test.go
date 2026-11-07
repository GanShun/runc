//go:build linux && !cgo

package libcontainer

import (
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/configs"
)

// TestCheckPuregoConfigRefusesTimeOffsets covers the one config field the cgo-free
// path cannot honour. The offsets are read only by the C constructor, so the
// clone(2) here would create a time namespace with none and nothing would say so.
func TestCheckPuregoConfigRefusesTimeOffsets(t *testing.T) {
	config := &configs.Config{
		Rootfs:     t.TempDir(),
		Namespaces: configs.Namespaces([]configs.Namespace{{Type: configs.NEWNS}, {Type: configs.NEWTIME}}),
		TimeOffsets: map[string]specs.LinuxTimeOffset{
			"monotonic": {Secs: 3600},
		},
	}
	err := checkPuregoConfig(config)
	if err == nil {
		t.Fatal("checkPuregoConfig allowed timeOffsets, want a refusal")
	}
	if !strings.Contains(err.Error(), "timeOffsets cannot be applied without cgo") {
		t.Errorf("err = %q, want it to name the field and the reason", err)
	}

	if err := checkPuregoConfig(&configs.Config{}); err != nil {
		t.Errorf("checkPuregoConfig refused a config without offsets: %v", err)
	}
	// An empty map asks for nothing; specconv passes a spec's empty
	// "timeOffsets": {} through as exactly this.
	if err := checkPuregoConfig(&configs.Config{TimeOffsets: map[string]specs.LinuxTimeOffset{}}); err != nil {
		t.Errorf("checkPuregoConfig refused an empty offset map: %v", err)
	}

	// And through Create, which is the call the caller actually makes. The
	// refusal has to arrive before anything privileged is attempted.
	_, err = Create(t.TempDir(), "timeoff", config)
	if err == nil {
		t.Fatal("Create accepted timeOffsets, want a refusal")
	}
	if !strings.Contains(err.Error(), "timeOffsets cannot be applied without cgo") {
		t.Errorf("Create: err = %q, want the timeOffsets refusal", err)
	}
}

// TestCheckPuregoConfigRefusesParentDeathSignal covers the configuration that
// cannot be honoured rather than the one that is merely unimplemented: the init is
// cloned with CLONE_PARENT, so its real parent is the runc thread that forked the
// stage, and arming PR_SET_PDEATHSIG against that thread kills a container whose
// runc is still alive the moment Go retires the thread.
func TestCheckPuregoConfigRefusesParentDeathSignal(t *testing.T) {
	config := &configs.Config{ParentDeathSignal: int(unix.SIGKILL)}
	err := checkPuregoConfig(config)
	if err == nil {
		t.Fatal("expected ParentDeathSignal to be refused")
	}
	if !strings.Contains(err.Error(), "ParentDeathSignal") {
		t.Errorf("error = %v, want it to name the field it refuses", err)
	}
}
