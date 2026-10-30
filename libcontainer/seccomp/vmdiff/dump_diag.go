//go:build seccomp_diag && ((cgo && seccomp) || (!cgo && linux))

package main

import (
	"fmt"
	"os"

	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/seccomp"
)

// cmdDump prints the program this build compiles for each named case, or for
// every case when none is named.
//
// Nothing here is a test and nothing installs a filter: the comparison is two
// builds printing their own programs and run.sh diffing the output, which is the
// same shape as the VM differential and needs neither a VM nor both compilers in
// one process.
func cmdDump(args []string) {
	want := make(map[string]bool, len(args))
	for _, a := range args {
		want[a] = true
	}
	cs := cases()
	if len(want) > 0 {
		// A mistyped case name must not read as an empty report.
		known := make(map[string]bool, len(cs))
		for i := range cs {
			known[cs[i].Name] = true
		}
		for name := range want {
			if !known[name] {
				fmt.Fprintf(os.Stderr, "dump: no case named %q\n", name)
				os.Exit(2)
			}
		}
	}

	fmt.Printf("# build %s\n", seccomp.BuildName())
	for i := range cs {
		c := &cs[i]
		if len(want) > 0 && !want[c.Name] {
			continue
		}
		fmt.Printf("### case %s\n", c.Name)
		prog, err := seccomp.ProgramFor(c.buildConfig())
		if err != nil {
			fmt.Printf("# error: %v\n", err)
			continue
		}
		for _, ins := range prog {
			fmt.Printf("%v\n", ins)
		}
	}
}

// ociArchitectures are the names configs.Seccomp.Architectures accepts
// (libcontainer/seccomp/config.go), listed so a diagnostic can ask each build
// what it does with one. A name added there and not here shows up as a missing
// row rather than a wrong one.
var ociArchitectures = []string{
	"amd64", "x86", "x32", "arm", "arm64",
	"mips", "mips64", "mips64n32", "mipsel", "mipsel64", "mipsel64n32",
	"ppc", "ppc64", "ppc64le", "riscv64", "s390", "s390x", "loongarch64",
}

// cmdArches prints, for each architecture, whether this build will filter it. The
// two builds answer differently by design (causes 6 and 7 in
// docs/seccomp-go-vs-libseccomp.md), and this is how that is read without a VM.
func cmdArches(args []string) {
	fmt.Printf("# build %s\n", seccomp.BuildName())
	for _, name := range ociArchitectures {
		cfg := &configs.Seccomp{
			DefaultAction: configs.Allow,
			Architectures: []string{name},
		}
		if _, err := seccomp.ProgramFor(cfg); err != nil {
			fmt.Printf("%-14s refused: %v\n", name, err)
			continue
		}
		fmt.Printf("%-14s ok\n", name)
	}
}
