# Roadmap: the cgo-free (`CGO_ENABLED=0`) port

This file tracks the cgo-free port of runc: what it does today, how each claim
was checked, and what is still open. It is deliberately evidence-first — every
claim carries a `file:line` or a command — because the reasons in a port like
this are load-bearing. The exit-255 failure that made every `runc exec`
unusable here was, for a while, attributed to the PID-namespace limitation; the
actual causes were three pieces of leftover cgo staging on the exec path, and
the PID namespace was a fourth, separate problem (`96f5e2bd`). "It looked like
the reason" is not a reason.

Each item is marked:

- **verified in code** — read in this tree;
- **observed running** — a run that exists, with somewhere a reader can find the
  record;
- **untested** — nobody has run it.

Line numbers refer to the tip of `purego-exec` (`26d0f5f5`), where the port is
complete; the file itself is on the `purego` base. Where a line is on an older
branch, the commit is named.

## Where the work is

| branch | contents |
| --- | --- |
| `purego` (`a22e3fac`) | the base: four commits by Ronald G. Minnich that are in `opencontainers/runc` but not on `main` (`9065153d`, `dfad5719`, `fc66d646`, `481f2ac5` — the `nsenter.go`/`nsenter_cgo.go` split and follow-ups), plus "create namespaces without cgo" (`7a54c08d`) and a fail-open seccomp warning (`02f8e85a`). PR [#1](https://github.com/GanShun/runc/pull/1) |
| `purego-seccomp` (`7215222c`) | eight commits that compile seccomp filters in Go (`20893ce2` … `7215222c`). PR [#2](https://github.com/GanShun/runc/pull/2) |
| `purego-exec` (`26d0f5f5`) | three commits that join namespaces by path and stage `runc exec` (`d8fe9e94`, `96f5e2bd`, `26d0f5f5`). PR [#3](https://github.com/GanShun/runc/pull/3) |

## 1. What this port is

runc normally does its namespace work in C: `libcontainer/nsenter/nsenter_cgo.go:10-17`
registers a constructor that runs `nsexec()` **before the Go runtime boots**,
because `setns(2)` and `unshare(2)` act on a single thread and a Go process is
multithreaded from startup. With `CGO_ENABLED=0` that constructor does not
exist — `libcontainer/nsenter/nsenter.go:1-6` is an empty package under `!cgo` —
so every job it did had to be done in Go or given up. The port covers namespace
creation, joining namespaces by path, seccomp filter compilation and the
PID-namespace staging `runc exec` needs; the parts that are given up are in §4.

The original constraint is timing, not capability. Go has no equivalent of the
constructor: there is no raw `fork(2)` that keeps running Go (`os/exec` always
follows `clone` with `execve`), so an operation that must happen before the
runtime exists, or in a process that must be created *after* a
`setns(CLONE_NEWPID)`, is reached by a different route here — a `clone(2)`
performed by the parent, or a re-exec of the same binary.

## 2. Working

### 2.1 Container init: namespaces created by the parent's `clone(2)`

**Verified in code:**

- `purego_nocgo.go:17-20` (`puregoNamespaces = true`) and `:37-42`
  (`setCloneFlags` assigns `cmd.SysProcAttr.Cloneflags`), with the cgo
  counterpart a no-op at `purego_cgo.go:13-16`.
- Call site: `container_linux.go:572-574`, guarded by `if p.Init`.
- Because the direct child *is* the container init, the parent takes its PID
  directly and never waits for a reported one:
  `process_linux.go:1005-1008`, with `waitForChildExit` skipped at `:1028-1033`.
  The cgo path is unchanged (`:1010-1016`).
- The netlink bootstrap payload, which only the C constructor could read, is
  built under `!puregoNamespaces` only (`container_linux.go:663-676`).

**Observed running:** the commit that introduced it (`7a54c08d`) records a
QEMU-booted kernel where a `CGO_ENABLED=0` runc ran a container whose
`/proc/self/status` reported `Pid: 1` with its own PID namespace. That run is
not reproducible from this repository alone (it needs a kernel and a rootfs);
it has not been repeated for this document.

### 2.2 Joining namespaces given by path (`d8fe9e94`)

**Verified in code:**

- Entry point: `init_linux.go:239-250` — the init process decodes its
  `initConfig`, then joins `config.NamespacePaths` *before* `containerInit`, so
  before anything that touches the network, the hostname or the mounts.
  `Init` has already called `runtime.GOMAXPROCS(1)` and
  `runtime.LockOSThread` (`init_linux.go:113-116`).
- `join_namespaces_nocgo.go:69-126`; the cgo build's version is a no-op
  (`join_namespaces_cgo.go:8`).
- The path list is built by `orderNamespacePaths` (`container_linux.go:1067-1096`)
  and attached at `container_linux.go:682` (init) and `:724` (exec).
  `Namespaces.CloneFlags()` deliberately skips any namespace with a `Path`
  (`configs/namespaces_syscall.go:24-33`), which is why the paths have to travel
  separately at all.

**Which types can be joined, and by what rule:**

| type | how | where |
| --- | --- | --- |
| net, ipc, uts, cgroup | `setns(fd, 0)` | `join_namespaces_nocgo.go:108-124` |
| mount | `unshare(CLONE_FS)` first, then `setns(fd, 0)` | `:116-120`, `:148-153` — `mntns_install` refuses a shared `fs_struct` (`fs/namespace.c:6496`, `fs->users != 1`), and Go's runtime creates every thread with `CLONE_FS`, so the fs must be detached first |
| user | refused, error | `:93-94` — see §4.1 |
| pid | refused for a container init, error | `:95-98` — see §4.2 |

Every descriptor is opened **before any of them is joined** (`:87-113`), because
after the mount join `/proc` is the container's procfs and the host pids the
remaining paths name are gone; nsexec says the same at `nsexec.c:646-651` and
does the same at `:651`. Join order is `configs/namespaces_linux.go:73-84`.

**Observed running:** `d8fe9e94`'s message records that the container had been
running in the host's namespaces while everything above it believed otherwise
(the container reported the host's address on `eth0`; it now reports the
namespace's), with the same assertion after a reboot. Not repeated here.

**Untested:** the join itself has no unit test, and cannot have an
unprivileged one — it needs a real `setns(2)`. `purego_nocgo_test.go:18-24`
says so; the wiring around it is what is unit-tested (`:26`, `:57`).

### 2.3 Seccomp filters compiled to BPF in Go

**Verified in code:**

- Compiler: `seccomp/bpf_linux.go:179` `compileFilter`; architecture dispatch
  `:263` `assembleFilter`; per-architecture section `:640`;
  the bad-architecture action is `KILL_THREAD` (`:79`, `:292`);
  rules are laid out as a balanced search tree over the syscall number
  (`:461`, `:471`); x32 numbers are recognised by bit 30 and refused
  (`:696-712`); an architecture with no table is refused (`:220-229`).
- The `-ENOSYS` stub is ported at `seccomp/bpf_enosys_linux.go:15-25` and
  prepended at `bpf_linux.go:239-248`.
- The syscall tables are generated, not hand-maintained:
  `seccomp/syscalls_linux.go` (14 architectures) from
  `seccomp/internal/mksyscalls/main.go:34-49`, `:84-105`, which parses
  `golang.org/x/sys/unix`'s per-architecture `zsysnum_*` files.
- Install: `seccomp/seccomp_nocgo.go:37-55`, with `seccomp(2)` and a `prctl(2)`
  fallback when no flags are needed (`:110-140`), flag translation (`:80-108`),
  `FlagSupported` (`:146-155`) and `Enabled = true` (`:163`).

**Observed running, and how it was checked.** The point of interest is not that
the compiler is self-consistent but that it agrees with an implementation
nobody here wrote. Two commands, both run for this document on this tree:

```
CGO_ENABLED=1 go test -tags seccomp ./libcontainer/seccomp/ -run TestAgainstLibseccomp -count=1 -v
# 11 profiles, 4278 cases, 0 differences, against libseccomp 2.5.5

CGO_ENABLED=0 go test ./libcontainer/seccomp/... -count=1
# ok — includes TestAgainstModel (5922 cases), TestSectionIsATree,
# TestProgramsWellFormed, TestEnosysStub, TestContainerdDefaultArchitectures
# and TestInitSeccompLoads (seccomp_nocgo_test.go:36), which installs real
# filters in a re-exec'd child so the test process is not filtered.
```

`TestAgainstLibseccomp` (`seccomp/differential_seccomp_test.go:1`, `:27`) is
the only test that compares the compiler with an implementation other than
itself; the model test is written from the same reading of the profile
semantics, so a shared misreading satisfies both. Its x32 carve-out is at
`:51-63`.

**Documentation drift:** the package comment at `seccomp/seccomp_nocgo.go:22-31`
still says the `-ENOSYS` stub and libseccomp's search tree "are not reproduced
here yet" and calls the filter "a linear chain". Both were added later
(`dc75bcb5`, `995a035c`) and both are tested above. The comment is the one place
in this port whose prose contradicts its code.

### 2.4 `runc exec`: staging into the container's PID namespace

**Why a process has to be created.** `setns(CLONE_NEWPID)` does not move the
caller: `pidns_install` stores the target in `pid_ns_for_children` and returns
(`kernel/pid_namespace.c:392-419`, quoted in §4.2). Only the caller's *next
child* is created there, and `execve(2)` creates no process, so "setns, then
exec the next stage" cannot join a PID namespace. nsexec forks after the setns
(`nsexec.c:1132`); Go cannot fork and keep running Go, but it can fork and
re-exec — which is what `os/exec` does — and the next stage here is a fresh
program, so nothing has to survive the fork.

**Verified in code:**

- The stage: `runcns_linux.go:32` (`RuncNsCommand`), `:46-52` (entry, never
  returns), `:95-131` (`LockOSThread` at `:118`, open the path at `:120`,
  `setns(CLONE_NEWPID)` at `:124`), `:134-188` (start the next stage with
  `Cloneflags: CLONE_PARENT` at `:167`, report the PID at `:179-186`,
  `CloseOnExec` on the report fd at `:140`).
- The parent: `purego_nocgo.go:65-107` `stageExecNs` rewrites the exec command
  into `os.Executable() runcns <pid-ns-path> <init-path> <runc argv0> init …`
  (`:101-104`), appends one report pipe to `cmd.ExtraFiles` (`:84-87`) and
  removes the PID path from the list the init stage will join (`:66-69`,
  `:109-120`); `container_linux.go:703-736` calls it from `newSetnsProcess`;
  `process_linux.go:630-678` branches `execSetns` and `:689-756`
  `adoptRuncNsChild` reads the reported PID, reaps the stage and adopts the
  process; `signals.go:70-80` records why `CLONE_PARENT` is load-bearing (the
  exec'd process must be runc's own child, or the `wait4(-1)` reap loop never
  reports it and `runc exec` hangs).
- Two guards the cgo staging used to provide and `!cgo` must not:
  `process_linux.go:513-517` (do not copy the netlink bootstrap payload onto the
  init pipe) and `container_linux.go:565-574` (do not apply `CloneFlags()` to an
  exec child — it would be cloned into a *new* PID namespace, from which the
  container's is unreachable, `pidns_install` only accepting a descendant).

**Why a subcommand of `runc`, not a second binary.** The stage's job is to start
`runc init`, and `runc init` is already a re-exec of this same binary
(`container_linux.go:532-550` builds `cmd.Path` as `/proc/self/fd/N` of a sealed
clone, or `/proc/self/exe` when already cloned; `init.go:10-26` dispatches the
subcommand before the CLI). nsexec has the same home: it is inside the runc
binary (`nsenter_cgo.go:10-17`). Keeping the stage there means the stage and the
runc that invokes it cannot be different versions, the report descriptor's name
has exactly one definition (`runcns_linux.go:34-38`), and there is no `PATH`
lookup or override to find or to test. The alternative — a separate `runc-ns`
helper — is what `96f5e2bd` shipped and `26d0f5f5` replaced.

**Observed running:** PR #3's description records the end-to-end check — the
exec'd process's `/proc/self/ns/pid` matches the container init's, and a real
CNI agent whose `postStart`/`preStop` hooks had been failing now starts with them
intact. **Verified here:** the staging's own unit tests pass unprivileged,

```
CGO_ENABLED=0 go test ./libcontainer/ -count=1
# ok — TestSplitPidNamespacePath (purego_nocgo_test.go:26),
# TestStageExecNsWiresStage (:57), TestStartExecNsStageStartsCallerParentedChild
# (:174), TestAdoptRuncNsChildAdoptsReportedPid (:247),
# TestAdoptRuncNsChildRefusesNonPositivePid (:287),
# TestAdoptRuncNsChildKillsUnadoptedProcess (:319)
```

They cover the argument, descriptor and report-pipe conventions and the
`CLONE_PARENT` parentage, not a real `setns(2)`.

## 3. Untested, with what would settle each

A gap with no test attached stays open indefinitely, so each item names the
command or assertion that would close it.

1. **The exec shapes other than a plain, short, zero-exit `runc exec`.** The
   hook case is covered, but not: `--detach` (`exec.go:65-67`, which also skips
   the signal handler, `utils_linux.go:270-272`), `--preserve-fds`
   (`exec.go:91`), a console socket (`exec.go:33`, wired into
   `cmd.ExtraFiles` at `container_linux.go:577-582`), a non-zero exit status
   coming back out, and the **no-PID-namespace branch** (`purego_nocgo.go:66-69`
   returns no stage at all; `process_linux.go:638-646` takes the direct-child
   model instead — a hand-written bundle is the only way to reach it, since a
   CRI container always has a PID namespace).
   *Would settle it:* a container plus `runc exec -d`, `runc exec --preserve-fds 1`,
   `runc exec --console-socket`, and an exec that exits non-zero — asserting the
   exit status reaches the caller in each case — and a bundle whose
   `config.json` has no `pid` namespace, asserting the exec'd process still
   starts and that `runcns` was not involved.

2. **Descriptor pass-through across the extra stage — the most likely remaining
   bug.** The staging inserts a process into runc's fd inheritance chain: every
   `_LIBCONTAINER_*` descriptor and every preserved fd now has to survive one
   more `execve` (`purego_nocgo.go:84-87`, `runcns_linux.go:87-91`, `:142-169`).
   Nothing is re-plumbed and the numbers are meant to be unchanged, but the
   in-guest evidence is a hook that uses no extra descriptors.
   *Would settle it:* `runc exec --preserve-fds 1` writing to fd 3 and having the
   parent read it back, plus `runc exec --console-socket` with a real terminal,
   plus reading `/proc/self/fd` inside the exec'd process and comparing it with
   what a `CGO_ENABLED=1` exec shows.

3. **`os.Executable()` as the stage's path when runc's own executable is a
   `memfd:` clone.** `stageExecNs` locates the stage with `os.Executable()`
   (`purego_nocgo.go:74`), which is `readlink /proc/self/exe`
   (`$(go env GOROOT)/src/os/executable_procfs.go:15-27`). When
   `exeseal.IsSelfExeCloned()` is true (`container_linux.go:532-538`), runc's own
   `/proc/self/exe` is a sealed memfd; `newParentProcess` handles that for
   `runc init` by using `/proc/self/exe` directly, and the stage has no
   equivalent.
   **Partially observed here:** a process exec'd from a memfd has
   `os.Executable()` return the memfd link with `" (deleted)"` trimmed, and that
   path does not exist:
   ```
   child os.Executable() = "/memfd:runc_cloned" err=<nil>
   child readlink /proc/self/exe = "/memfd:runc_cloned (deleted)"
   child os.Stat(exe) = stat /memfd:runc_cloned: no such file or directory
   ```
   (a throwaway Go program using a raw `memfd_create` syscall — 319 on amd64 —
   and `exec.Command("/proc/self/fd/3")`; runc's own memfd is named
   `runc_cloned:<comment>`, `libcontainer/exeseal/cloned_binary_linux.go:65-66`).
   So the *premise* is observed; whether `runc exec` reaches it is not.
   *Would settle it:* start runc from a sealed memfd clone of itself so
   `IsSelfExeCloned()` is true, then `runc exec` — a stage failure would surface
   as a bare `no such file or directory` from the exec, since the stage is
   exec'd by name.

4. **`setsid()`.** nsexec calls it in stage 2 (`nsexec.c:1195-1196`) and nothing
   in the Go path reproduces it: `grep -rn setsid libcontainer/` finds the syscall
   tables in `libcontainer/seccomp/syscalls_linux.go` and `nsexec.c:1195-1196`,
   and nothing in Go. This is a divergence from nsexec rather than
   something this port's staging introduced, and it applies to a container init
   as well as to an exec.
   *Would settle it:* inside a container and inside an exec'd process, compare
   `Getpid()`, `Getpgid(0)` and `getsid(0)` — with `setsid` called, the process
   is its own session and process-group leader. A `CGO_ENABLED=1` run is the
   reference.

5. **`ParentDeathSignal`.** `container_linux.go:637-639` sets `Pdeathsig` on the
   process runc starts directly, whatever `p.Init` is. In the exec path that
   process is now the `runcns` stage, which exits immediately after reporting
   the PID, and the process it creates inherits nothing either: `copy_process`
   clears the field for every new task (`kernel/fork.c:2377`) and the signal is
   delivered only to a dying task's children at reparenting time
   (`kernel/exit.c:746-755`). Whether the cgo build's stage-0 arrangement
   delivers it to an exec'd process either is not something this port changed,
   and neither path has been measured.
   *Would settle it:* `prctl(PR_GET_PDEATHSIG)` read inside the container init
   and inside an exec'd process, for both `CGO_ENABLED=0` and `CGO_ENABLED=1`
   builds, plus a bundle that sets `ParentDeathSignal` and a killed runc — the
   exec'd process must receive it.

6. **Mount-source remapping.** The `procMountPlease`/`procMountFd` handshake
   that lets runc's own (host-side, privileged) thread open a mount source for
   the container is wired only for the container init:
   `process_linux.go:1041-1048` gives the request handler to `initProcess`, and
   `setnsProcess` treats a request as a bug and panics
   (`process_linux.go:560-562`). It is reached from the init's rootfs setup
   (`rootfs_linux.go:101-126`), which an exec does not run, so this is an
   untested configuration rather than a known break — the same `unshare(CLONE_FS)`
   pattern it uses on its own locked thread is the precedent `detachFs` follows
   (`process_linux.go:858-861`; `join_namespaces_nocgo.go:145-147`).
   *Would settle it:* a bundle with an idmapped mount (`MOUNT_ATTR_IDMAP`) or a
   bind mount whose source cannot be resolved from inside the container, run
   under `CGO_ENABLED=0`, asserting the container starts and the mount is
   present in `/proc/self/mountinfo`.

7. **A container *init* that joins a mount namespace by path.** Only an exec has
   ever had a mount namespace in its path list, which is the case `detachFs` was
   written for. For an init, `config.Rootfs` is an absolute path resolved by the
   creating process (`libcontainer/specconv/spec_linux.go:396-399`), and
   `prepareRootfs` opens it by path (`rootfs_linux.go:166`), while
   `joinNamespaces` has already run
   (`init_linux.go:248`, before `containerInit`). So the configuration could
   fail before `pivotRoot` rather than in it — but no configuration has reached
   it at all.
   *Would settle it:* a bundle with a `mount` namespace entry carrying a `path`,
   asserting the container reaches a running state (and, if it does not, which
   of the two opens fails).

## 4. Not supported, with the kernel reason

### 4.1 User namespaces / rootless

`userns_install` refuses a caller that is not single-threaded, and a Go process
never is:

```c
// kernel/user_namespace.c:1343-1359
	/* Tasks that share a thread group must share a user namespace */
	if (!thread_group_empty(current))
		return -EINVAL;

	if (current->fs->users != 1)
		return -EINVAL;
```

So joining one is refused outright (`join_namespaces_nocgo.go:93-94`).
*Creating* one is the other half: a single `clone(2)` with `CLONE_NEWUSER` plus
the other namespaces returns `EPERM`, which is the ordering nsexec works around
by unsharing the user namespace first, letting the parent write
`uid_map`/`gid_map`, and unsharing the rest afterwards. That staging does not
exist in Go here (`purego_nocgo.go:26-28`). `SysProcAttr` does support
`UidMappings`/`GidMappings`; the staged unshare is the missing piece. Rootful
containers, which is what this port is for, are unaffected.

### 4.2 Joining a PID namespace by path, for a container init

```c
// kernel/pid_namespace.c:392-419
	put_pid_ns(nsproxy->pid_ns_for_children);
	nsproxy->pid_ns_for_children = get_pid_ns(new);
	return 0;
```

The caller does not move — only its next child is created in the target — so a
`setns(2)` alone cannot join one, and a container init needs a fork that
continues the same program, which Go cannot do. It is refused, not skipped
(`join_namespaces_nocgo.go:95-98`); the namespace is created by `clone(2)`
instead, which is what makes the child PID 1 (§2.1). For `runc exec` the same
kernel rule is satisfied by re-exec rather than a raw fork (§2.4). The
ancestor rule in the same function (`:410`, `pidns_is_ancestor`) is why the
stage's own `setns` only works while the container's namespace is a descendant
of runc's, and `nr = pid_vnr(pid)` (`kernel/fork.c:2761`) is why the PID the
stage reports is the host PID runc needs.

### 4.3 Checkpoint/restore (CRIU)

Not supported here, but for a provenance reason rather than a kernel one, and
this is worth stating plainly: I could not find a kernel rule that this port
violates, and nothing in it implements or blocks CRIU. `Container.Restore` and
`Container.Checkpoint` hand the work to an external `criu` binary
(`criu_linux.go:636`, `criu_linux.go:925`, guarded by a version check at `:649`);
`criu_linux.go` carries no `cgo` build tag, so it compiles in this build. The
honest status is therefore **untested**, with no evidence either way.
*Would settle it:* with `criu` on `PATH` and a `CGO_ENABLED=0` runc,
`runc create` + `runc start`, then `runc checkpoint` and `runc restore` —
asserting the restored container's PID is unchanged and that `/proc/self/status`
still reports the container's PID namespace. If it fails, the failure will name
the missing piece; until then, "not supported" here means "not tried".

### 4.4 Seccomp for architectures with no syscall table

`golang.org/x/sys/unix` has no per-architecture syscall-number table for x32,
the two mips n32 ABIs, or 31-bit s390 (`seccomp/internal/mksyscalls/main.go:9-11`;
the generated `syscalls_linux.go` has 14 tables, and the 18 names in
`seccomp/config.go:50-69` include those four). Such an architecture is left out
of the dispatch and warned about (`bpf_linux.go:220-229`), and the filter's
bad-architecture action then refuses it — `KILL_THREAD`, matching libseccomp,
which is not the same filter as `KILL_PROCESS` for a threaded process
(`bpf_linux.go:79`, `:288-292`). x32 additionally needs bit 30 of the syscall
number, because `seccomp_data.arch` is `AUDIT_ARCH_X86_64` for both x86-64 and
x32; those numbers are refused too (`bpf_linux.go:696-712`).

Refusing rather than filtering with the wrong numbering is deliberate, and the
argument is fail-closed versus fail-open: a syscall-number table for the wrong
ABI produces a filter that judges the wrong numbers, and for an allow rule that
means allowing what the profile denies. The differential test records the same
asymmetry from the other side: it excludes x32 numbers only for profiles that
list `SCMP_ARCH_X32`, because libseccomp resolves them with a table this build
does not have (`seccomp/differential_seccomp_test.go:51-63`). A profile that
lists an architecture without a table is still accepted; that architecture is
refused instead of being silently unfiltered.

## 5. Toolchain notes

`CGO_ENABLED=0 go vet ./libcontainer/...` fails, and it is **pre-existing at the
port's base**, not caused by it:

```
$ CGO_ENABLED=0 go vet ./libcontainer/...
# github.com/opencontainers/runc/libcontainer/nsenter/test
# [github.com/opencontainers/runc/libcontainer/nsenter/test]
vet: libcontainer/nsenter/test/escape_test.go:10:2: undefined: testEscapeJSON
```

The cause is `libcontainer/nsenter/test/escape.go`: it imports `"C"`
(`escape.go:1-11`, with the comment "The actual test function is in escape.go so
that it can use cgo (import \"C\")"), so under `CGO_ENABLED=0` the file is
excluded and the `testEscapeJSON` that `escape_test.go:10` calls is undefined.
It reports as a missing symbol rather than as an `import "C"` error because the
build constraint removes the whole file.

Checked at the base (`git worktree add --detach <dir> a22e3fac`, then the
command above): the same message on the same line. The last commit to touch
`escape.go` is `928ef7af` ("libct/nsenter: add json msg escaping"), an ancestor
of the base, and the file is byte-identical between the base and `purego-exec`.
That package is the only one that fails. With cgo it is clean:

```
$ CGO_ENABLED=1 go vet ./libcontainer/...   # exit 0, at the base and at purego-exec
```

So: `CGO_ENABLED=1 go vet ./libcontainer/...` is the usable check for this port,
and the `!cgo` vet failure should not be read as a defect of the port. Fixing it
would mean moving that one test out from behind `import "C"`; it is upstream's
test, and it is left alone here.
