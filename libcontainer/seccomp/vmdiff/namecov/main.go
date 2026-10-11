//go:build linux && cgo

// Command namecov compares the kernel-header syscall name -> number tables
// (libcontainer/seccomp/syscalls_linux.go) against the names libseccomp
// resolves, per architecture.
//
// It is the tool that found the name-coverage divergence written up in
// docs/seccomp-go-vs-libseccomp.md, and it still shows which kernel-header
// names libseccomp does not resolve (the ones the generated
// libseccomp_linux.go drops) and which it resolves differently. The compiler
// itself no longer resolves from the kernel-header table, so this is a check on
// the generator's candidate list rather than on the compiler; see the README.
//
// It installs nothing; it only asks both sides to resolve names. For each
// architecture it reports:
//
//   - names the kernel-header table has and libseccomp cannot resolve, so a
//     rule naming one is dropped by both builds now that the compiler resolves
//     from the generated libseccomp table;
//   - names both resolve but to different numbers (libseccomp's multiplexing
//     pseudo-numbers are the bulk of this);
//   - names only libseccomp resolves, from a candidate list.
//
// Usage (from the runc checkout):
//
//	go run ./libcontainer/seccomp/vmdiff/namecov
//	go run ./libcontainer/seccomp/vmdiff/namecov -extra candidates.txt
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	libseccomp "github.com/seccomp/libseccomp-golang"
)

// archPairs maps the Go table's SCMP_ARCH_* key to libseccomp's ScmpArch.
var archPairs = []struct {
	goName string
	scmp   libseccomp.ScmpArch
}{
	{"SCMP_ARCH_X86", libseccomp.ArchX86},
	{"SCMP_ARCH_X86_64", libseccomp.ArchAMD64},
	{"SCMP_ARCH_X32", libseccomp.ArchX32},
	{"SCMP_ARCH_ARM", libseccomp.ArchARM},
	{"SCMP_ARCH_AARCH64", libseccomp.ArchARM64},
	{"SCMP_ARCH_LOONGARCH64", libseccomp.ArchLOONGARCH64},
	{"SCMP_ARCH_MIPS", libseccomp.ArchMIPS},
	{"SCMP_ARCH_MIPS64", libseccomp.ArchMIPS64},
	{"SCMP_ARCH_MIPS64N32", libseccomp.ArchMIPS64N32},
	{"SCMP_ARCH_MIPSEL", libseccomp.ArchMIPSEL},
	{"SCMP_ARCH_MIPSEL64", libseccomp.ArchMIPSEL64},
	{"SCMP_ARCH_MIPSEL64N32", libseccomp.ArchMIPSEL64N32},
	{"SCMP_ARCH_PPC", libseccomp.ArchPPC},
	{"SCMP_ARCH_PPC64", libseccomp.ArchPPC64},
	{"SCMP_ARCH_PPC64LE", libseccomp.ArchPPC64LE},
	{"SCMP_ARCH_RISCV64", libseccomp.ArchRISCV64},
	{"SCMP_ARCH_S390", libseccomp.ArchS390},
	{"SCMP_ARCH_S390X", libseccomp.ArchS390X},
}

var (
	archRe  = regexp.MustCompile(`^\t"(SCMP_ARCH_[A-Z0-9_]+)": \{$`)
	entryRe = regexp.MustCompile(`^\t\t"([a-zA-Z0-9_]+)":\s+(\d+),$`)
)

func main() {
	tablesFile := flag.String("tables", "libcontainer/seccomp/syscalls_linux.go", "path to the generated Go syscall tables")
	extraFile := flag.String("extra", "", "extra candidate names, one per line, to probe on the libseccomp side only")
	flag.Parse()

	goTables, err := parseTables(*tablesFile)
	if err != nil {
		fatal(err)
	}

	var extra []string
	if *extraFile != "" {
		data, err := os.ReadFile(*extraFile)
		if err != nil {
			fatal(err)
		}
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				extra = append(extra, l)
			}
		}
	}

	ma, mi, mu := libseccomp.GetLibraryVersion()
	fmt.Printf("libseccomp %d.%d.%d; Go tables from %s: %d architectures\n\n", ma, mi, mu, *tablesFile, len(goTables))

	for _, p := range archPairs {
		goTable, ok := goTables[p.goName]
		if !ok {
			fmt.Printf("== %-14s (libseccomp %v): NO GO TABLE\n\n", strings.TrimPrefix(p.goName, "SCMP_ARCH_"), p.scmp)
			continue
		}

		fmt.Printf("== %-14s (%d names)\n", strings.TrimPrefix(p.goName, "SCMP_ARCH_"), len(goTable))

		oursOnly, numMismatch := []string{}, []string{}
		for name, num := range goTable {
			nr, err := libseccomp.GetSyscallFromNameByArch(name, p.scmp)
			if err != nil {
				oursOnly = append(oursOnly, fmt.Sprintf("%s=%d", name, num))
				continue
			}
			if int32(nr) != int32(num) {
				numMismatch = append(numMismatch, fmt.Sprintf("%s: go %d libseccomp %d", name, num, int32(nr)))
			}
		}
		sort.Strings(oursOnly)
		sort.Strings(numMismatch)

		if len(oursOnly) > 0 {
			fmt.Printf("   go-only (Go build enforces, libseccomp drops): %d\n", len(oursOnly))
			printWrapped(oursOnly, 8)
		}
		if len(numMismatch) > 0 {
			fmt.Printf("   NUMBER MISMATCH (different syscall filtered!): %d\n", len(numMismatch))
			for _, m := range numMismatch {
				fmt.Printf("      %s\n", m)
			}
		}
		var libOnly []string
		for _, name := range extra {
			if _, known := goTable[name]; known {
				continue
			}
			if nr, err := libseccomp.GetSyscallFromNameByArch(name, p.scmp); err == nil {
				libOnly = append(libOnly, fmt.Sprintf("%s=%d", name, int32(nr)))
			}
		}
		sort.Strings(libOnly)
		if len(libOnly) > 0 {
			fmt.Printf("   libseccomp-only (libseccomp enforces, Go drops): %d\n", len(libOnly))
			printWrapped(libOnly, 8)
		}
		fmt.Println()
	}
}

// parseTables reads the generated syscallNumbers map out of syscalls_linux.go.
// A regex is enough: the file is generated, and its shape is fixed.
func parseTables(path string) (map[string]map[string]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tables := map[string]map[string]uint32{}
	var arch string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if m := archRe.FindStringSubmatch(line); m != nil {
			arch = m[1]
			tables[arch] = map[string]uint32{}
			continue
		}
		if m := entryRe.FindStringSubmatch(line); m != nil && arch != "" {
			var n uint32
			if _, err := fmt.Sscanf(m[2], "%d", &n); err != nil {
				return nil, err
			}
			tables[arch][m[1]] = n
			continue
		}
		if strings.TrimSpace(line) == "}," && arch != "" {
			arch = ""
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("%s: no tables parsed; is it the generated file?", path)
	}
	return tables, nil
}

func printWrapped(items []string, perLine int) {
	for i := 0; i < len(items); i += perLine {
		end := i + perLine
		if end > len(items) {
			end = len(items)
		}
		fmt.Printf("      %s\n", strings.Join(items[i:end], "  "))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "namecov:", err)
	os.Exit(1)
}
