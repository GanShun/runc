//go:build linux && cgo && seccomp

package gen

import (
	"strings"
	"testing"
)

// TestCheckVersionRefusesMismatch pins the deliberate-regeneration rule: the
// generator only runs against the libseccomp the tables are pinned to, and the
// refusal names both versions and where to change the pin.
func TestCheckVersionRefusesMismatch(t *testing.T) {
	if err := CheckVersion("2.5.5", "2.5.5"); err != nil {
		t.Fatalf("CheckVersion refused matching versions: %v", err)
	}
	err := CheckVersion("2.5.5", "2.5.6")
	if err == nil {
		t.Fatal("CheckVersion accepted a mismatched version")
	}
	for _, want := range []string{"2.5.6", "2.5.5", "PinnedLibseccompVersion"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
}

// TestGenerateRefusesMismatchedPin checks that Generate applies the pin before
// it reads anything: a deliberately wrong expected version is refused even
// though the candidate file does not exist, so the guard cannot be skipped by a
// missing input.
func TestGenerateRefusesMismatchedPin(t *testing.T) {
	_, err := Generate("this-file-does-not-exist.go", "9.9.9")
	if err == nil {
		t.Fatal("Generate accepted a wrong pinned version")
	}
	if !strings.Contains(err.Error(), "refusing to generate") {
		t.Errorf("Generate error does not read as a refusal: %v", err)
	}
}
