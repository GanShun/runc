//go:build linux && !cgo

package libcontainer

import (
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"

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
