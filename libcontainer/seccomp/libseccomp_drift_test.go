//go:build linux && cgo && seccomp

package seccomp

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/opencontainers/runc/libcontainer/seccomp/internal/mkseccomptables/gen"
)

// The committed tables and the generated kernel-header tables they use as a
// candidate name list, both relative to this package's directory.
const (
	generatedTablePath = "libseccomp_linux.go"
	candidateNamesPath = "syscalls_linux.go"
)

// TestGeneratedTablesMatchCommitted is the staleness guard for
// libseccomp_linux.go.
//
// The cgo-free compiler resolves syscall names from the committed table, while
// the cgo build resolves them from whatever libseccomp it links against. If the
// committed table is stale, a name the linked libseccomp knows is absent from
// it, and a profile that denies that name has its rule dropped by the cgo-free
// build and enforced by the cgo build. For a deny rule that is fail-open, and
// nothing else in the test suite would notice, because the drop is otherwise
// silent.
//
// This test regenerates the tables from the libseccomp linked into this test
// binary -- the same library the cgo build in this configuration uses -- and
// compares the result with the committed file byte for byte. It also checks the
// version the committed file records against the host, which catches a version
// bump that happens to change no table entry. So a stale table, a hand-edited
// entry, or a hand-edited version all fail here.
//
// It needs cgo and libseccomp, so it carries `cgo && seccomp` and does not
// exist for the CGO_ENABLED=0 build. Where libseccomp cannot be queried it is
// skipped with a message rather than passing silently.
func TestGeneratedTablesMatchCommitted(t *testing.T) {
	host := gen.VersionString()
	if host == "0.0.0" {
		t.Skip("libseccomp is not available here (seccomp_version() returned 0.0.0), " +
			"so the committed tables cannot be checked against it")
	}

	committed, err := os.ReadFile(generatedTablePath)
	if err != nil {
		t.Fatalf("reading the committed table %s: %v", generatedTablePath, err)
	}

	if libseccompGeneratedVersion != host {
		t.Fatalf("the committed table records libseccomp %s, but this host links %s;\n"+
			"the cgo-free build would resolve names from stale tables.\n"+
			"Regenerate against the pinned version, or bump gen.PinnedLibseccompVersion\n"+
			"and regenerate deliberately:\n\n"+
			"\tCGO_ENABLED=1 go run -tags seccomp ./libcontainer/seccomp/internal/mkseccomptables\n",
			libseccompGeneratedVersion, host)
	}

	res, err := gen.Generate(candidateNamesPath, gen.PinnedLibseccompVersion)
	if err != nil {
		t.Fatalf("regenerating the tables in memory: %v", err)
	}

	if bytes.Equal(res.Source, committed) {
		return
	}
	t.Errorf("the committed table %s differs from one generated from libseccomp %s.\n"+
		"The cgo-free build enforces the committed table, so regenerate it:\n\n"+
		"\tCGO_ENABLED=1 go run -tags seccomp ./libcontainer/seccomp/internal/mkseccomptables\n\n%s",
		generatedTablePath, res.Version, firstDifference(committed, res.Source))
}

// firstDifference describes the first line where two generated files differ, so
// a failure points at the entry rather than printing two six-thousand-line
// files.
func firstDifference(committed, fresh []byte) string {
	want := strings.Split(string(committed), "\n")
	got := strings.Split(string(fresh), "\n")
	for i := 0; i < len(want) || i < len(got); i++ {
		var a, b string
		if i < len(want) {
			a = want[i]
		}
		if i < len(got) {
			b = got[i]
		}
		if a != b {
			return fmt.Sprintf("first difference at line %d:\n  committed: %s\n  generated: %s\n"+
				"(%d committed lines, %d generated lines)",
				i+1, a, b, len(want), len(got))
		}
	}
	return "the files differ only in trailing data"
}
