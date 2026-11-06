# Roadmap: the cgo-free (`CGO_ENABLED=0`) port

This file tracks the cgo-free port of runc: what it does today, how each claim
was checked, and what is still open. It is deliberately evidence-first — every
claim names a file and the function, type or variable inside it, or a command —
because the reasons in a port like this are load-bearing. The exit-255 failure
that made every `runc exec` unusable here was, for a while, attributed to the
PID-namespace limitation; the actual causes were three pieces of leftover cgo
staging on the exec path, and the PID namespace was a fourth, separate problem
(the `runcns` staging). "It looked like the reason" is not a
reason.

Each item is marked:

- **verified in code** — read in this tree;
- **observed running** — a run that exists, with somewhere a reader can find the
  record;
- **untested** — nobody has run it.

A reference names a file and the function, type or variable inside it, never a
line number: a line number moves with every unrelated edit above it while the
number written here does not. References name branches rather than commits for
the same reason. Referenced code lives on `local-main`, which carries the port,
with the exec staging included. A path
is relative to `libcontainer/` unless it starts with
`libcontainer/` (repository-relative), is a Linux kernel source (`kernel/`,
`fs/`), or is `nsexec.c` (`libcontainer/nsenter/nsexec.c`). This file itself
ships with the port.

## Where the work is

| branch | contents |
| --- | --- |
| `main` | the mirror of `opencontainers/runc`; never committed to |
| `purego` | a **pure mirror** of u-root's `purego`: the `nsenter.go`/`nsenter_cgo.go` split and its follow-ups, which are not on `main`. It carries no work of ours |
| **`local-main`** | the default branch: u-root's `purego` plus the port — namespaces without cgo, the Go seccomp compiler with its model, differential and interpreter tests, the `vmdiff` kernel harness, the tests that pin what each architecture does, and joining namespaces by path with the `runcns` staging for `runc exec` |
| `roadmap` | `local-main` plus this document |
| `docs` | `local-main` plus the three long-form studies under `docs/` |

## 1. What this port is

runc normally does its namespace work in C:
`libcontainer/nsenter/nsenter_cgo.go` registers a constructor that runs
`nsexec()` **before the Go runtime boots**, because `setns(2)` and `unshare(2)`
act on a single thread and a Go process is multithreaded from startup. With
`CGO_ENABLED=0` that constructor does not exist —
`libcontainer/nsenter/nsenter.go` is an empty package under `!cgo` — so every
job it did had to be done in Go or given up. The port covers namespace
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

- `purego_nocgo.go`: the `puregoNamespaces` constant and `setCloneFlags`, which
  assigns `cmd.SysProcAttr.Cloneflags`, with the cgo counterpart a no-op in
  `purego_cgo.go`.
- Call site: `container_linux.go`, in `newParentProcess`, guarded by `if p.Init`.
- Because the direct child *is* the container init, the parent takes its PID
  directly and never waits for a reported one: `process_linux.go`, in
  `initProcess.start`, which also skips `waitForChildExit`; the cgo path in the
  same function is unchanged.
- The netlink bootstrap payload, which only the C constructor could read, is
  built under `!puregoNamespaces` only (`container_linux.go`, in
  `newInitProcess`).

**Observed running:** the commit that introduced it (`libcontainer: create
namespaces without cgo`, on `purego`) records a
QEMU-booted kernel where a `CGO_ENABLED=0` runc ran a container whose
`/proc/self/status` reported `Pid: 1` with its own PID namespace. That run is
not reproducible from this repository alone (it needs a kernel and a rootfs);
it has not been repeated for this document.

### 2.2 Joining namespaces given by path

**Verified in code:**

- Entry point: `init_linux.go`, in `startInitialization` — the init process
  decodes its `initConfig`, then joins `config.NamespacePaths` *before*
  `containerInit`, so before anything that touches the network, the hostname or
  the mounts. `Init` has already called `runtime.GOMAXPROCS(1)` and
  `runtime.LockOSThread` (same file, `Init`).
- `join_namespaces_nocgo.go`, `joinNamespaces`; the cgo build's version is a
  no-op (`join_namespaces_cgo.go`).
- The path list is built by `orderNamespacePaths` (`container_linux.go`) and
  attached in `newInitProcess` (init) and `newSetnsProcess` (exec).
  `Namespaces.CloneFlags()` deliberately skips any namespace with a `Path`
  (`configs/namespaces_syscall.go`), which is why the paths have to travel
  separately at all.

**Which types can be joined, and by what rule:**

| type | how | where |
| --- | --- | --- |
| net, ipc, uts, cgroup | `setns(fd, 0)` | `join_namespaces_nocgo.go`, `joinNamespaces` |
| mount | `unshare(CLONE_FS)` first (`detachFs`), then `setns(fd, 0)` | `join_namespaces_nocgo.go`, `joinNamespaces` and `detachFs` — `mntns_install` refuses a shared `fs_struct` (`fs/namespace.c`, `fs->users != 1`), and Go's runtime creates every thread with `CLONE_FS`, so the fs must be detached first |
| user | refused, error | `joinNamespaces` — see §4.1 |
| pid | refused for a container init, error | `joinNamespaces` — see §4.2 |

Every descriptor is opened **before any of them is joined** (`joinNamespaces`),
because after the mount join `/proc` is the container's procfs and the host pids
the remaining paths name are gone; nsexec says the same and does the same in
`nsexec.c`'s `join_namespaces`. Join order is `configs/namespaces_linux.go`, in
`NamespaceTypes`.

**Observed running:** that commit's message records that the container had been
running in the host's namespaces while everything above it believed otherwise
(the container reported the host's address on `eth0`; it now reports the
namespace's), with the same assertion after a reboot. Not repeated here.

**Untested:** the join itself has no unit test, and cannot have an
unprivileged one — it needs a real `setns(2)`. `purego_nocgo_test.go` says so;
the wiring around it is what is unit-tested, in `TestSplitPidNamespacePath` and
`TestStageExecNsWiresStage`.

### 2.3 Seccomp filters compiled to BPF in Go

**Verified in code:**

- Compiler: `seccomp/bpf_linux.go`, `compileFilter`; architecture dispatch
  `assembleFilter`; per-architecture section `compileArchSection`;
  the bad-architecture action is `KILL_THREAD` (`retKillThread`, emitted by
  `assembleFilter`);
  rules are laid out as a balanced search tree over the syscall number
  (`treeEmitter`); x32 numbers are recognised by bit 30 and refused
  (`assembleFilter`, `compileArchSection`); an architecture with no table is
  refused (`compileFilter`, via `archSyscallTables`).
- The `-ENOSYS` stub is ported at `seccomp/bpf_enosys_linux.go` (`enosysStub`)
  and prepended in `compileFilter`.
- The syscall tables are generated, not hand-maintained:
  `seccomp/syscalls_linux.go` (14 architectures) from
  `seccomp/internal/mksyscalls/main.go` (`goarchToSeccomp`, `parseSysnums`),
  which parses `golang.org/x/sys/unix`'s per-architecture `zsysnum_*` files.
- Install: `seccomp/seccomp_nocgo.go`, `InitSeccomp`, with `seccomp(2)` and a
  `prctl(2)` fallback when no flags are needed (`loadFilter`), flag translation
  (`filterFlags`), `FlagSupported` and `Enabled = true`.
- `TSYNC` is always paired with `TSYNC_ESRCH` (`filterFlags`), because `TSYNC`
  and `NEW_LISTENER` both return a value and the kernel refuses the pair without
  it: a profile asking for `tsync` that also has a `notify` rule could not load
  at all. A failed synchronisation then surfaces as a **positive thread id with
  errno 0** rather than an error, so the return value is read too
  (`seccompFilterResult`). Reading only errno reports success while a thread runs
  unfiltered, which is the one thing a profile asking for `tsync` is for.

**Observed running, and how it was checked.** The point of interest is not that
the compiler is self-consistent but that it agrees with an implementation
nobody here wrote. Two commands, both run for this document on this tree:

```
CGO_ENABLED=1 go test -tags seccomp ./libcontainer/seccomp/ -run TestAgainstLibseccomp -count=1 -v
# 11 profiles, 4278 cases, 0 differences, against libseccomp 2.5.5

CGO_ENABLED=0 go test ./libcontainer/seccomp/... -count=1
# ok — includes TestAgainstModel (5922 cases), TestSectionIsATree,
# TestProgramsWellFormed, TestEnosysStub, TestContainerdDefaultArchitectures
# and TestInitSeccompLoads, which installs real filters in a re-exec'd child
# so the test process is not filtered.
```

`TestAgainstLibseccomp` (`seccomp/differential_seccomp_test.go`) is
the only test that compares the compiler with an implementation other than
itself; the model test is written from the same reading of the profile
semantics, so a shared misreading satisfies both. Its x32 carve-out is inside
`TestAgainstLibseccomp`.

The `TSYNC` pairing is checked against the kernel, not only as a bit pattern:
`TestTsyncWithNotifyLoads` (`seccomp/seccomp_nocgo_tsync_test.go`) installs a real
`tsync` + `notify` filter in a child process and requires it to load. Without
`TSYNC_ESRCH` it fails with `error loading seccomp filter: invalid argument` on
Linux 6.8 — measured, not inferred.

### 2.4 `runc exec`: staging into the container's PID namespace

**Why a process has to be created.** `setns(CLONE_NEWPID)` does not move the
caller: `pidns_install` stores the target in `pid_ns_for_children` and returns
(`kernel/pid_namespace.c`, quoted in §4.2). Only the caller's *next child* is
created there, and `execve(2)` creates no process, so "setns, then exec the next
stage" cannot join a PID namespace. nsexec forks after the setns (`nsexec.c`,
in `nsexec()`); Go cannot fork and keep running Go, but it can fork and re-exec —
which is what `os/exec` does — and the next stage here is a fresh program, so
nothing has to survive the fork.

**Verified in code:**

- The stage: `runcns_linux.go` — `RuncNsCommand`; `RunRuncNs` (entry, never
  returns); `runRuncNs` (`LockOSThread`, open the path, `setns(CLONE_NEWPID)`);
  `startExecNsStage` (start the next stage with `Cloneflags: CLONE_PARENT`,
  report the PID, `CloseOnExec` on the report fd).
- The parent: `purego_nocgo.go`, `stageExecNs`, rewrites the exec command into
  `<cmd.Path> runcns <pid-ns-path> <init-path> <runc argv0> init …`, appends one
  report pipe to `cmd.ExtraFiles` and removes the PID path from the list the init
  stage will join (`splitPidNamespacePath`); `container_linux.go`,
  `newSetnsProcess`, calls it; `process_linux.go`, `setnsProcess.execSetns`,
  branches to `setnsProcess.adoptRuncNsChild`, which reads the reported PID,
  reaps the stage and adopts the process; `signals.go`,
  `signalHandler.forward`, records why `CLONE_PARENT` is load-bearing (the exec'd
  process must be runc's own child, or the `wait4(-1)` reap loop never reports
  it and `runc exec` hangs).
- The stage is exec'd by the path `newParentProcess` already built for `runc
  init` — a sealed `/proc/self/fd/N` descriptor, or `/proc/self/exe` when runc is
  itself a clone — and not by `os.Executable()`, which under a memfd clone names
  a path that does not exist (§3, item 3). That path is also what the stage
  passes on as `initExe`, and it stays valid across the extra `execve` because
  the descriptor is in `cmd.ExtraFiles`. Its `argv[0]`, in contrast, is runc's
  own: an operator reads it in `ps`, and dispatch reads `os.Args[1]` (`init.go`,
  `init`), so a descriptor path there would be noise.
- Two guards the cgo staging used to provide and `!cgo` must not:
  `process_linux.go`, `setnsProcess.start` (do not copy the netlink bootstrap
  payload onto the init pipe) and `container_linux.go`, `newParentProcess` (do
  not apply `CloneFlags()` to an exec child — it would be cloned into a *new*
  PID namespace, from which the container's is unreachable, `pidns_install` only
  accepting a descendant).

**Why a subcommand of `runc`, not a second binary.** The stage's job is to start
`runc init`, and `runc init` is already a re-exec of this same binary
(`container_linux.go`, `newParentProcess`, builds `cmd.Path` as
`/proc/self/fd/N` of a sealed clone, or `/proc/self/exe` when already cloned;
`init.go`, `init`, dispatches the subcommand before the CLI). nsexec has the
same home: it is inside the runc binary
(`libcontainer/nsenter/nsenter_cgo.go`). Keeping the stage there means the stage
and the runc that invokes it cannot be different versions, the report
descriptor's name has exactly one definition (`runcns_linux.go`,
`runcNsReportFdEnv`), and there is no `PATH` lookup or override to find or to
test. The alternative — a separate `runc-ns` helper — is what `libcontainer:
stage runc exec into the container PID namespace without cgo` shipped and
`libcontainer: make the exec PID-namespace stage a runc subcommand` replaced.

**Observed running:** PR #3's description records the end-to-end check — the
exec'd process's `/proc/self/ns/pid` matches the container init's, and a real
CNI agent whose `postStart`/`preStop` hooks had been failing now starts with them
intact. **Verified here:** the staging's own unit tests pass unprivileged,

```
CGO_ENABLED=0 go test ./libcontainer/ -count=1
# ok — TestSplitPidNamespacePath, TestStageExecNsWiresStage,
# TestStartExecNsStageStartsCallerParentedChild,
# TestAdoptRuncNsChildAdoptsReportedPid,
# TestAdoptRuncNsChildRefusesNonPositivePid,
# TestAdoptRuncNsChildKillsUnadoptedProcess   (purego_nocgo_test.go)
```

They cover the argument, descriptor and report-pipe conventions and the
`CLONE_PARENT` parentage, not a real `setns(2)`.

## 3. Untested, with what would settle each

A gap with no test attached stays open indefinitely, so each item names the
command or assertion that would close it.

1. **The exec shapes other than a plain, short, zero-exit `runc exec`.** The
   hook case is covered, but not: `--detach` (`exec.go`, the `execCommand`
   definition, which also skips the signal handler, `utils_linux.go`,
   `runner.run`), `--preserve-fds` (`exec.go`, `execCommand`), a console socket
   (`exec.go`, `execCommand`, wired into `cmd.ExtraFiles` in
   `container_linux.go`, `newParentProcess`), a non-zero exit status coming back
   out, and the **no-PID-namespace branch** (`purego_nocgo.go`, `stageExecNs`,
   returns no stage at all; `process_linux.go`, `setnsProcess.execSetns`, takes
   the direct-child model instead — a hand-written bundle is the only way to
   reach it, since a CRI container always has a PID namespace).
   *Would settle it:* a container plus `runc exec -d`, `runc exec --preserve-fds 1`,
   `runc exec --console-socket`, and an exec that exits non-zero — asserting the
   exit status reaches the caller in each case — and a bundle whose
   `config.json` has no `pid` namespace, asserting the exec'd process still
   starts and that `runcns` was not involved.

2. **Descriptor pass-through across the extra stage — the most likely remaining
   bug.** The staging inserts a process into runc's fd inheritance chain: every
   `_LIBCONTAINER_*` descriptor and every preserved fd now has to survive one
   more `execve` (`purego_nocgo.go`, `stageExecNs`; `runcns_linux.go`,
   `startExecNsStage`). Nothing is re-plumbed and the numbers are meant to be
   unchanged, but the in-guest evidence is a hook that uses no extra
   descriptors.
   *Would settle it:* `runc exec --preserve-fds 1` writing to fd 3 and having the
   parent read it back, plus `runc exec --console-socket` with a real terminal,
   plus reading `/proc/self/fd` inside the exec'd process and comparing it with
   what a `CGO_ENABLED=1` exec shows.

3. **`runc exec` when runc's own executable is a `memfd:` clone.** This was a
   hazard in `stageExecNs`, which located the stage with `os.Executable()` while
   runc's own `/proc/self/exe` was a sealed memfd; the code now execs the stage
   by the path `newParentProcess` built (`purego_nocgo.go`, `stageExecNs`, and
   §2.4), so the hazard is closed by construction and
   `TestStageExecNsWiresStage` asserts the wiring — the sealed path, and the
   descriptor numbering in `cmd.ExtraFiles` that keeps it valid across the extra
   `execve`. What is **not** observed is the run itself: no environment here
   starts a memfd-cloned runc (§2.4). The premise it rests on, that
   `os.Executable()` cannot be used for this, is observed: a process exec'd from
   a memfd has `os.Executable()` return the memfd link with `" (deleted)"`
   trimmed, and that path does not exist:
   ```
   child os.Executable() = "/memfd:runc_cloned" err=<nil>
   child readlink /proc/self/exe = "/memfd:runc_cloned (deleted)"
   child os.Stat(exe) = stat /memfd:runc_cloned: no such file or directory
   ```
   (a throwaway Go program using a raw `memfd_create` syscall — 319 on amd64 —
   and `exec.Command("/proc/self/fd/3")`; runc's own memfd is named
   `runc_cloned:<comment>`, `libcontainer/exeseal/cloned_binary_linux.go`,
   `Memfd`).
   *Would settle it:* start runc from a sealed memfd clone of itself so
   `IsSelfExeCloned()` is true, then `runc exec` — a stage failure would surface
   as a bare `no such file or directory` from the exec.

4. **`setsid()`.** nsexec calls it in stage 2 (`nsexec.c`, `nsexec()`) and
   nothing in the Go path reproduces it: `grep -rn setsid libcontainer/` finds
   the syscall tables in `libcontainer/seccomp/syscalls_linux.go` and
   `nsexec.c`, and nothing in Go. This is a divergence from nsexec rather than
   something this port's staging introduced, and it applies to a container init
   as well as to an exec.
   *Would settle it:* inside a container and inside an exec'd process, compare
   `Getpid()`, `Getpgid(0)` and `getsid(0)` — with `setsid` called, the process
   is its own session and process-group leader. A `CGO_ENABLED=1` run is the
   reference.

5. **`ParentDeathSignal`.** `container_linux.go`, `newParentProcess`, sets
   `Pdeathsig` on the process runc starts directly, whatever `p.Init` is. In the
   exec path that process is now the `runcns` stage, which exits immediately
   after reporting the PID, and the process it creates inherits nothing either:
   `copy_process` clears the field for every new task (`kernel/fork.c`) and the
   signal is delivered only to a dying task's children at reparenting time
   (`kernel/exit.c`). Whether the cgo build's stage-0 arrangement delivers it to
   an exec'd process either is not something this port changed, and neither path
   has been measured.
   *Would settle it:* `prctl(PR_GET_PDEATHSIG)` read inside the container init
   and inside an exec'd process, for both `CGO_ENABLED=0` and `CGO_ENABLED=1`
   builds, plus a bundle that sets `ParentDeathSignal` and a killed runc — the
   exec'd process must receive it.

6. **Mount-source remapping.** The `procMountPlease`/`procMountFd` handshake
   that lets runc's own (host-side, privileged) thread open a mount source for
   the container is wired only for the container init: `process_linux.go`,
   `initProcess.start`, gives the request handler to `initProcess`, and
   `setnsProcess` treats a request as a bug and panics (`process_linux.go`,
   `setnsProcess.start`). It is reached from the init's rootfs setup
   (`rootfs_linux.go`, `setupAndMountToRootfs`), which an exec does not run, so
   this is an untested configuration rather than a known break — the same
   `unshare(CLONE_FS)` pattern it uses on its own locked thread is the precedent
   `detachFs` follows (`process_linux.go`,
   `initProcess.goCreateMountSources`; `join_namespaces_nocgo.go`, `detachFs`).
   *Would settle it:* a bundle with an idmapped mount (`MOUNT_ATTR_IDMAP`) or a
   bind mount whose source cannot be resolved from inside the container, run
   under `CGO_ENABLED=0`, asserting the container starts and the mount is
   present in `/proc/self/mountinfo`.

7. **A container *init* that joins a mount namespace by path.** Only an exec has
   ever had a mount namespace in its path list, which is the case `detachFs` was
   written for. For an init, `config.Rootfs` is an absolute path resolved by the
   creating process (`libcontainer/specconv/spec_linux.go`,
   `CreateLibcontainerConfig`), and `prepareRootfs` opens it by path
   (`rootfs_linux.go`), while `joinNamespaces` has already run (`init_linux.go`,
   `startInitialization`, before `containerInit`). So the configuration could
   fail before `pivotRoot` rather than in it — but no configuration has reached
   it at all.
   *Would settle it:* a bundle with a `mount` namespace entry carrying a `path`,
   asserting the container reaches a running state (and, if it does not, which
   of the two opens fails).

8. **The `TSYNC_ESRCH` fallback for kernels older than 5.7.** `loadFilter`
   (`seccomp/seccomp_nocgo.go`) retries without `TSYNC_ESRCH` if the kernel
   rejects the flag with `EINVAL` and no listener was asked for, because that flag
   arrived in 5.7 and an older kernel reports a failed synchronisation *only* by
   returning a positive thread id. A kernel that knows the flag never takes the
   retry, so this tree cannot reach the branch: it is verified in code and untested
   in behaviour.
   Such a kernel cannot express `tsync` together with `notify` at all, so the
   question is only whether the retry degrades honestly: a plain `tsync` profile
   must still load, and `tsync` + `notify` must fail with the kernel's `EINVAL`
   rather than install a filter on no thread.
   *Would settle it:* boot a pre-5.7 kernel in the `vmdiff` VM (`run.sh`, which
   already takes a kernel image) and run
   `CGO_ENABLED=0 go test ./libcontainer/seccomp/ -count=1` there.
   `TestTsyncWithNotifyLoads` skips on such a kernel — it probes the flag with a
   raw `seccomp(2)` first and reports the kernel as lacking it — so the run to
   read is the rest of the package plus an explicit attempt at `tsync` + `notify`,
   asserting the `EINVAL`.

9. **The whole of `libcontainer/integration` — the suite that checks any of the
   above against a real container.** It needs root: it creates namespaces,
   mounts, cgroups and containers. `.gitlab-ci.yml` carries a
   `libcontainer-integration` job for it, `manual` and `allow_failure`, and it
   **probes first**: `unshare --mount --pid --fork` and a writable
   `cgroup.controllers`. Measured on the shared runner (pipeline 588, job 1586):
   the probe fails in 0.4 s because the runner's pod has no `CAP_SYS_ADMIN`. So
   the job is a tripwire that becomes a gate the day a privileged runner exists,
   not a check that passes.
   Two consequences to keep honest: the container-level claims in §2 rest on the
   consumer's cluster test (a kubelet joining a throwaway control plane and
   running pods under this runc), not on runc's own suite; and the job's
   expected-failure step asserts that `TestInitJoinPID`,
   `TestInitJoinNetworkAndUser`, `TestExecInUserns` and `TestExecInUsernsRlimit`
   fail *and* report the documented refusal, so a limitation that quietly
   disappears is noticed rather than counted as a pass.
   *Would settle it:* a runner with `privileged: true` and a writable cgroupfs, or
   the same tests cross-built and run inside the k4s node image, which boots as
   root with `CAP_SYS_ADMIN`.

## 4. Not supported, with the kernel reason

### 4.1 User namespaces / rootless

`userns_install` refuses a caller that is not single-threaded, and a Go process
never is:

```c
// kernel/user_namespace.c, userns_install
	/* Tasks that share a thread group must share a user namespace */
	if (!thread_group_empty(current))
		return -EINVAL;

	if (current->fs->users != 1)
		return -EINVAL;
```

So joining one is refused outright (`join_namespaces_nocgo.go`,
`joinNamespaces`). The same test refuses a *time* namespace: `timens_install`
returns `EUSERS` when `!current_is_single_threaded()`
(`kernel/time/namespace.c`), and nsexec joins one only because the C
constructor runs before the runtime starts. Both are refused with an error that
says why rather than the kernel's `EINVAL`/"too many users", which does not.
*Creating* one is the other half: a single `clone(2)` with
`CLONE_NEWUSER` plus the other namespaces returns `EPERM`, which is the ordering
nsexec works around by unsharing the user namespace first, letting the parent
write `uid_map`/`gid_map`, and unsharing the rest afterwards. That staging does
not exist in Go here (`purego_nocgo.go`, `setCloneFlags`). `SysProcAttr` does
support `UidMappings`/`GidMappings`; the staged unshare is the missing piece.
Rootful containers, which is what this port is for, are unaffected.

### 4.2 Joining a PID namespace by path, for a container init

```c
// kernel/pid_namespace.c, pidns_install
	put_pid_ns(nsproxy->pid_ns_for_children);
	nsproxy->pid_ns_for_children = get_pid_ns(new);
	return 0;
```

The caller does not move — only its next child is created in the target — so a
`setns(2)` alone cannot join one, and a container init needs a fork that
continues the same program, which Go cannot do. It is refused, not skipped
(`join_namespaces_nocgo.go`, `joinNamespaces`); the namespace is created by
`clone(2)` instead, which is what makes the child PID 1 (§2.1). For `runc exec`
the same kernel rule is satisfied by re-exec rather than a raw fork (§2.4). The
ancestor rule in the same function (`pidns_is_ancestor`) is why the stage's own
`setns` only works while the container's namespace is a descendant of runc's,
and `nr = pid_vnr(pid)` (`kernel/fork.c`) is why the PID the stage reports is
the host PID runc needs.

**What this costs a pod.** Two shapes cannot start, and both are ordinary in a
Kubernetes cluster:

- `shareProcessNamespace: true`, where the app containers are given the pause
  container's PID namespace by path;
- ephemeral containers from `kubectl debug --target=<container>`, which are
  given the target's PID namespace by path.

The mechanism that would fix it is the one §2.4 adds for `runc exec`: start the
init stage through `RuncNsCommand`, carry the init's clone flags onto its
`clone(2)`, and adopt the reported PID in `initProcess.start()` before the cgroup
is applied, as `adoptRuncNsChild` does. Two things to get right: the
parent-death signal under `CLONE_PARENT`, and the cgroup-namespace root on the
path that does not use `CLONE_INTO_CGROUP`. Upstream's `TestInitJoinPID` is the
acceptance test (it needs root). The consumer-side check belongs in k4s: a
`shareProcessNamespace` pod in `make test-cluster`.

### 4.3 Checkpoint/restore (CRIU)

Not supported here, but for a provenance reason rather than a kernel one, and
this is worth stating plainly: I could not find a kernel rule that this port
violates, and nothing in it implements or blocks CRIU. `Container.Restore` and
`Container.Checkpoint` hand the work to an external `criu` binary
(`criu_linux.go`, `Restore` and `Checkpoint`, guarded by a version check in
`checkCriuVersion`); `criu_linux.go` carries no `cgo` build tag, so it compiles
in this build. The honest status is therefore **untested**, with no evidence
either way.
*Would settle it:* with `criu` on `PATH` and a `CGO_ENABLED=0` runc,
`runc create` + `runc start`, then `runc checkpoint` and `runc restore` —
asserting the restored container's PID is unchanged and that `/proc/self/status`
still reports the container's PID namespace. If it fails, the failure will name
the missing piece; until then, "not supported" here means "not tried".

### 4.4 Seccomp for architectures with no syscall table

`golang.org/x/sys/unix` has no per-architecture syscall-number table for x32,
the two mips n32 ABIs, or 31-bit s390 (`seccomp/internal/mksyscalls/main.go`;
the generated `syscalls_linux.go` has 14 tables, and the 18 names in
`seccomp/config.go`, the `archs` table and `KnownArchs`, include those four).
Such an architecture is left out of the dispatch and warned about
(`seccomp/bpf_linux.go`, `compileFilter`), and the filter's bad-architecture
action then refuses it — `KILL_THREAD`, matching libseccomp, which is not the
same filter as `KILL_PROCESS` for a threaded process (`seccomp/bpf_linux.go`,
`retKillThread` and `assembleFilter`). x32 additionally needs bit 30 of the
syscall number, because `seccomp_data.arch` is `AUDIT_ARCH_X86_64` for both
x86-64 and x32; those numbers are refused too (`seccomp/bpf_linux.go`,
`assembleFilter` and `compileArchSection`).

Refusing rather than filtering with the wrong numbering is deliberate, and the
argument is fail-closed versus fail-open: a syscall-number table for the wrong
ABI produces a filter that judges the wrong numbers, and for an allow rule that
means allowing what the profile denies. The differential test records the same
asymmetry from the other side: it excludes x32 numbers only for profiles that
list `SCMP_ARCH_X32`, because libseccomp resolves them with a table this build
does not have (`seccomp/differential_seccomp_test.go`, inside
`TestAgainstLibseccomp`). A profile that lists an architecture without a table
is still accepted; that architecture is refused instead of being silently
unfiltered.

### 4.5 Time namespaces

Two things are refused, for the same reason: the offsets reach the kernel
through the C constructor and nothing else.

**Offsets are refused** (`purego_nocgo.go`, `checkPuregoConfig`, called from
`factory_linux.go`, `Create`). `container_linux.go` puts them in the netlink
payload (`TimeOffsetsAttr`, built when the time namespace is not being joined),
and nsexec's stage 0 writes that payload to `/proc/<pid>/timens_offsets`
(`nsexec.c`, `update_timens_offsets`). Under `puregoNamespaces` the payload is
not built at all, while `Namespaces.CloneFlags()` still includes `CLONE_NEWTIME`,
so `clone(2)` creates the namespace and the offsets are simply never applied: the
container would see a zero offset and nothing would report it. Refusing is the
fail-closed choice, and an **empty** map (`"timeOffsets": {}`) is not refused,
because it asks for nothing.

**Joining a time namespace by path is refused** (`join_namespaces_nocgo.go`):
`timens_install` requires a single-threaded caller and returns `EUSERS`
otherwise (`kernel/time/namespace.c`), and a Go process is never single-threaded.
The same test already refuses the user namespace (`userns_install`,
`kernel/user_namespace.c`).

A future path exists that this port has not taken: the container init is itself
created in the new time namespace by the parent's `clone(2)`, so it could write
its own `/proc/self/timens_offsets` before `execve`. Nothing here does that, and
whether it is safe against the container's own PID-namespace and mount state is
untested.

## 5. Toolchain notes

`CGO_ENABLED=0 go vet ./libcontainer/...` fails, and it is **pre-existing at the
port's base**, not caused by it:

```
$ CGO_ENABLED=0 go vet ./libcontainer/...
# github.com/opencontainers/runc/libcontainer/nsenter/test
# [github.com/opencontainers/runc/libcontainer/nsenter/test]
vet: libcontainer/nsenter/test/escape_test.go:10:2: undefined: testEscapeJSON
```

The cause is `libcontainer/nsenter/test/escape.go`: it imports `"C"` (with the
comment "The actual test function is in escape.go so that it can use cgo
(import \"C\")"), so under `CGO_ENABLED=0` the file is excluded and the
`testEscapeJSON` that `TestEscapeJSON` calls in `escape_test.go` is undefined.
It reports as a missing symbol rather than as an `import "C"` error because the
build constraint removes the whole file.

Checked at the base (`git worktree add --detach <dir> purego`, then the command
above): the same message on the same line. The last commit to touch `escape.go`
is "libct/nsenter: add json msg escaping", an ancestor of the base, and the file
is byte-identical between the base and `local-main`. That package is the only
one that fails. With cgo it is clean:

```
$ CGO_ENABLED=1 go vet ./libcontainer/...   # exit 0, at the base and on local-main
```

So: `CGO_ENABLED=1 go vet ./libcontainer/...` is the usable check for this port,
and the `!cgo` vet failure should not be read as a defect of the port. Fixing it
would mean moving that one test out from behind `import "C"`; it is upstream's
test, and it is left alone here.
