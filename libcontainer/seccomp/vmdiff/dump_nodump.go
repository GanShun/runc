//go:build !(seccomp_diag && ((cgo && seccomp) || (!cgo && linux)))

package main

import (
	"fmt"
	"os"
)

// cmdDump and cmdArches need a way to obtain the compiled program, which the
// seccomp package only offers under the seccomp_diag build tag. Build with it:
//
//	CGO_ENABLED=0 go build -tags seccomp_diag ./libcontainer/seccomp/vmdiff
//	CGO_ENABLED=1 go build -tags "seccomp seccomp_diag" ./libcontainer/seccomp/vmdiff
//
// run.sh dump does that for both builds and diffs the output.
func cmdDump(args []string) {
	notBuilt("dump")
}

func cmdArches(args []string) {
	notBuilt("arches")
}

func notBuilt(what string) {
	fmt.Fprintf(os.Stderr,
		"%s: build with -tags seccomp_diag (see run.sh dump), this binary was not\n", what)
	os.Exit(2)
}
