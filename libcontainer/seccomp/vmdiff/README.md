# vmdiff: runc's two seccomp builds, side by side, in a VM

`libcontainer/seccomp` compiles a profile in one of two ways depending on how
runc is built:

| build | compiler |
| --- | --- |
| `CGO_ENABLED=0` | `bpf_linux.go`, pure Go |
| `CGO_ENABLED=1 -tags seccomp` | libseccomp, plus `patchbpf` |

This harness compiles the same source both ways, boots both binaries inside a
QEMU VM, installs one filter per profile in a short-lived child process, issues
one raw syscall per (profile, probe) pair, and compares what the *kernel* did.
The findings are written up in
[`docs/seccomp-go-vs-libseccomp.md`](../../../../../docs/seccomp-go-vs-libseccomp.md).

It is **amd64-only by construction**: it drives the amd64, i386 (`int 0x80`) and
x32 syscall entry paths, so `main.go`, `cases.go` and the probe assembly carry
`//go:build linux && amd64`. Building it for another architecture is not
supported rather than merely untested.

It exists because `TestAgainstLibseccomp` compares the two compiled programs in
the `x/net/bpf` interpreter. That catches a wrong jump, but the interpreter is
not the kernel, and it skips the cases where the two builds are known to
disagree -- which is where the interesting differences are.

## Running it

```
./run.sh [kernel-image]
```

- `KERNEL=/path/to/vmlinuz` -- kernel to boot. A readable kernel image is
  fetched without root like this:

  ```
  curl -O https://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-6.8.0-146-generic_6.8.0-146.146_amd64.deb
  dpkg-deb -x linux-image-unsigned-*.deb /tmp/kern
  ```

- `VMDIFF_ONLY=a,b` -- restrict to named cases.
- `VMDIFF_FULL=1` -- print both raw reports, not just the divergences.
- `VMDIFF_PROGRESS=1` -- trace progress to the guest console.
- `TIMEOUT=600` -- QEMU wall-clock limit.

`/dev/kvm` is used when it is available. A full run is about 991 pairs per build
and takes well under a minute.

## Nothing touches the host

Installing a seccomp filter is irreversible for the process that installs it,
so every filter is installed by a child process **inside the VM**. The host runs
QEMU and nothing else. (On the host the harness cannot even install a filter:
`prctl(PR_SET_SECCOMP)` returns `EPERM` without `CAP_SYS_ADMIN`.)

## How a result is measured

Each (case, probe) pair runs as its own process:

1. The child maps a shared memory page (passed as fd 3) and computes everything
   the probe needs *before* the filter exists.
2. It installs the filter.
3. `probeAndStore` -- hand-written assembly -- issues exactly one syscall,
   stores `r1`/`errno`/flags into the shared page, and never returns to Go.
4. The parent polls the page, sees the answer the moment it is stored, and
   kills the child.

The assembly step is not decoration. A filter that denies the Go runtime's own
syscalls makes the runtime kill the process (with a `SIGTRAP` from its fatal
path) before the probe could run, which is what the `offStage` markers in the
result page exist to diagnose. Doing the probe in assembly removes the Go
runtime from the window entirely.

A `KILL_THREAD` action kills only the offending thread, so the Go process stays
alive; the parent's deadline catches that, and a probe with `Survivor` set
distinguishes it from `KILL_PROCESS` by having a second thread report that it
outlived the probe. That survivor needs a `P` of its own -- the killed thread
still holds the one it had -- so children run with `GOMAXPROCS=2`
(`VMDIFF_GOMAXPROCS` overrides it). A child that died before issuing the probe is retried and
reported as a harness failure if it persists, so a harness problem cannot be
mistaken for a filter difference.

Each child also records the profile it installed; the parent compares that with
what it expected, so a mis-indexed case cannot produce a finding.

## Adding a case

A case is a `Case` in `cases.go`: a default action, an architecture list, flags,
and rules. A probe is a `Probe`: an ABI (`amd64`, `i386` via `int 0x80`, or
`x32`), a syscall number, and arguments. Probes marked `Core` run under every
case; the rest are named by a case's `Probes` field.

Two rules for choosing probe arguments:

- do not pass a descriptor the harness needs (the result page is fd 3, and
  `os/exec` leaves 4 open), and
- make the probe's natural result distinguishable from the errnos a filter is
  likely to return, or the observation says nothing.

`run.sh` prints one line per divergent pair and a count. Two runs produce
identical reports modulo the addresses in a Go traceback.

## Comparing the syscall name tables

`namecov` asks libseccomp to resolve every name in the kernel-header tables
(`libcontainer/seccomp/syscalls_linux.go`) and reports where the two disagree --
names only one side knows, and names both know but number differently. It
installs nothing.

It is a diagnostic for the *generator's input*, not for what the compiler uses:
`libcontainer/seccomp` resolves names from `libseccomp_linux.go`, which
`internal/mkseccomptables` generates from libseccomp itself. What `namecov`
still shows usefully is which names were in the kernel-header candidate list and
what libseccomp makes of them; a "libseccomp-only" entry with a negative number
is a name libseccomp adds no rule for, and one with a positive number is a name
the generated table now carries.

```
go run ./libcontainer/seccomp/vmdiff/namecov
go run ./libcontainer/seccomp/vmdiff/namecov -extra candidates.txt
```

## Looking at the compiled programs without installing anything

```
VMDIFF_DIAG=1 CGO_ENABLED=1 go test -tags seccomp -run TestVMDiffDumpPrograms -v ./libcontainer/seccomp/
VMDIFF_DIAG=1 CGO_ENABLED=1 go test -tags seccomp -run TestVMDiffArchCompat -v ./libcontainer/seccomp/
```
