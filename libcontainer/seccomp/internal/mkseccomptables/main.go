//go:build linux && cgo && seccomp

// Command mkseccomptables generates the syscall name -> number and
// multiplexor tables the cgo-free seccomp compiler resolves names with.
//
// The extraction itself is in internal/mkseccomptables/gen, so that the drift
// test in libcontainer/seccomp can call it in memory; this command is the
// deliberate, manual way to rewrite the committed file. It refuses to run
// against a libseccomp whose version differs from the pin, so bumping the pin
// is an explicit act.
//
// Usage (from the runc checkout, with libseccomp available):
//
//	CGO_ENABLED=1 go run -tags seccomp ./libcontainer/seccomp/internal/mkseccomptables
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/seccomp/internal/mkseccomptables/gen"
)

func main() {
	syscallsFile := flag.String("syscalls", "libcontainer/seccomp/syscalls_linux.go",
		"path to the generated kernel-header tables, used only for candidate names")
	out := flag.String("o", "libcontainer/seccomp/libseccomp_linux.go",
		"output file (\"-\" for stdout)")
	expect := flag.String("expect-version", gen.PinnedLibseccompVersion,
		"libseccomp version this generation is for; a mismatch is refused. "+
			"Override only to watch the refusal fire, never to bypass the pin")
	flag.Parse()

	res, err := gen.Generate(*syscallsFile, *expect)
	if err != nil {
		fatal(err)
	}
	if *out == "" || *out == "-" {
		os.Stdout.Write(res.Source)
		return
	}
	if err := os.WriteFile(*out, res.Source, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d architectures, libseccomp %s)\n",
		*out, len(res.Architectures), res.Version)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mkseccomptables:", err)
	os.Exit(1)
}
