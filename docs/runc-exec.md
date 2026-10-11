> This study is the mechanism and the measurements behind the decision
> recorded in the workspace repository `k4s-agent`,
> `docs/adr/0002-runc-exec-runcns-subcommand.md`.

# `runc exec` in the cgo-free fork

This note answers a narrower question than its title: `runc exec` fails on this
node with

```
OCI runtime exec failed: exec failed: unable to start container process:
error executing setns process: exit status 255
```

and both `postStart` and `preStop` fail with it, so no container lifecycle hook
can run. The obvious suspect is the PID-namespace refusal that
`docs/nsenter-and-runc.md` describes. **It is not the cause.** The 255 is
produced by three places where the `runc exec` path still carries the cgo
staging that the `CGO_ENABLED=0` build cannot satisfy. The PID namespace is a
real limitation, but it sits *after* the failure, and fixing the three
non-PID defects would already let lifecycle hooks run. This note pins down
each step, then prices the options for doing `exec` properly.

The fork is only half-ported: `initProcess.start()` got a `puregoNamespaces`
branch, and `setnsProcess.start()` did not.

**Status: fixed, and verified in the guest.** Section 6 is the implementation
that makes `exec` work (the fork's `runcns` subcommand plus changes in
this fork's `libcontainer/`); sections 1–5 are kept as the study that found the
failure, and read in the present tense of when they were written. Two defects the
study did not find (the mount-namespace join and the namespace-fd open order)
are also in §6, and a review of the fix found more (an unadopted process leaked
on a report error, and the `CLONE_PIDFD` claim in §6 corrected below); those are
fixed too. The staging used to be a separate `runc-ns` helper binary in *this*
repository, packaged as a `bb` applet; §6 records why it moved into the fork and
became a subcommand.

---

## 1. The exact failure path

### The chain as reported

`../k4s/DIT:134` builds runc with `CGO_ENABLED=0`, so the binary on the node is the
`nocgo` path (`purego_nocgo.go`, `puregoNamespaces = true`). The error text is
produced by four wrappers, each one turn of a screw:

- `exec.go:114` — the CLI turns any error into exit 255:
  `fatalWithCode(fmt.Errorf("exec failed: %w", err), 255)`.
- `libcontainer/container_linux.go:399` — `unable to start container process: %w`.
- `libcontainer/process_linux.go:486-488` — `error executing setns process: %w`,
  wrapping the `exec.ExitError` that `execSetns` returns.
- `libcontainer/init_linux.go:129` — `os.Exit(255)`, a literal `os.Exit` in
  `Init()`, not a Go-runtime panic.

So "exit status 255" is the *child's* exit code, not the parent's.

### What the child does

`runc init` runs `Init()` (`init_linux.go:113`), which calls
`startInitialization()` and, if it returns, prints the error and exits 255.
`startInitialization` reads the init pipe and makes exactly one assumption
about what is on it:

```go
// libcontainer/init_linux.go:240
var config initConfig
if err := json.NewDecoder(initPipe).Decode(&config); err != nil {
    return err
}
```

In the cgo build that is safe: the C constructor has already consumed a netlink
bootstrap message from the same fd, and the JSON config follows it. In the
`nocgo` build there is no constructor (`libcontainer/nsenter/nsenter.go` is an
empty package under `!cgo`, `nsenter.go:1-6`), so nothing consumes it — but the
parent still writes it.

`newSetnsProcess` still builds bootstrap data:

```go
// libcontainer/container_linux.go:689
data, err := c.bootstrapData(0, state.NamespacePaths)
...
// libcontainer/container_linux.go:705
bootstrapData: data,
```

`bootstrapData` always returns a reader — there is no code path that returns
nil (`container_linux.go:1078-1194`, ending
`return bytes.NewReader(r.Serialize()), nil` at `:1194`) — and
`setnsProcess.start()` copies it to the init pipe unconditionally:

```go
// libcontainer/process_linux.go:481-485
if p.bootstrapData != nil {
    if _, err := io.Copy(p.comm.initSockParent, p.bootstrapData); err != nil {
        return fmt.Errorf("error copying bootstrap data to pipe: %w", err)
    }
}
```

`io.Copy` sees a non-nil reader from `bytes.NewReader`, so the copy always runs
in the `nocgo` build. The first four serialized bytes of
`nl.NewNetlinkRequest(InitMsg, 0).Serialize()` are `Len = 16` little-endian, so
the child's JSON decoder sees `0x10` as the first byte. I confirmed the exact
outcome with a standalone reproduction outside the repo:

```
first byte = 0x10
decode error: invalid character '\x10' looking for beginning of value
```

The decoder error is returned, and then something surprising happens. The
deferred function in `startInitialization` (`init_linux.go:148-162`) treats any
return as "initialization failed", writes the message to the *sync* pipe as a
`procError`, and then **clears the named return**:

```go
// libcontainer/init_linux.go:148-162
defer func() {
    if syncPipe.isClosed() { return }
    ierr := initError{Message: retErr.Error()}
    if err := writeSyncArg(syncPipe, procError, ierr); err != nil {
        fmt.Fprintln(os.Stderr, err)
        return
    }
    // The error is sent, no need to also return it (or it will be reported twice).
    retErr = nil
}()
```

So `Init()` receives `nil`, does not print, and exits 255. The only copy of the
diagnosis is sitting unread in the sync socket. The parent never reads it: it
is blocked in `execSetns`, which is called *before* `parseSync`. This is why the
kubelet message is the bare `exit status 255` with no child stderr, and why
there is nothing useful in the harness logs
(`../k4s/scripts/test-cluster.sh:425-445` records the same message).

### Where 255 is turned into a Go error

```go
// libcontainer/process_linux.go:598-628
func (p *setnsProcess) execSetns() error {
    status, err := p.cmd.Process.Wait()   // :599
    ...
    if !status.Success() {                 // :604
        _ = p.cmd.Wait()
        return &exec.ExitError{ProcessState: status}  // :606
    }
    var pid *pid
    if err := json.NewDecoder(p.comm.initSockParent).Decode(&pid); err != nil { // :609
    ...
```

The parent blocks on `Wait()` for the direct child to exit. In the cgo build
that direct child is nsexec stage 0, which exits as soon as stage 2 has setns'd
and been reported. In the `nocgo` build the direct child *is* the exec process,
so "wait for it to exit" is the wrong shape for the whole function, not just
for the pid decode. That is defect B below, and it is why the current failure
is not merely a missing error message.

### The three defects

**A. The exec child is fed a netlink bootstrap message nothing consumes.**
`process_linux.go:481-485` copies `p.bootstrapData`, which `newSetnsProcess`
still builds at `container_linux.go:689`. The `initProcess` path was fixed for
exactly this (`process_linux.go:848-852` skips the copy under
`puregoNamespaces`); the `setnsProcess` path was not touched. This is the
immediate cause of the 255: the child's first read is `json.Decode` at
`init_linux.go:240`, and the first byte is the netlink header.

**B. `execSetns` implements the cgo staging for a build that has no stage 0.**
`execSetns` waits for the direct child to exit and then decodes a
`stage2_pid`/`stage1_pid` JSON object that nsexec writes
(`nsexec.c:937-940`). Neither exists without cgo. Even if A were fixed, the
parent would block on `Wait()` while the child blocks reading the
`initConfig` JSON that the parent only writes *after* `execSetns`
(`process_linux.go:506`) — a deadlock, and then a failed pid decode. The
`initProcess` path avoided all of this by taking `p.cmd.Process.Pid` directly
and dropping `waitForChildExit` (`process_linux.go:848-876`).

**C. `setCloneFlags` is applied to the exec child too.** It is called before
the `p.Init` branch:

```go
// libcontainer/container_linux.go:565
setCloneFlags(cmd, c.config.Namespaces.CloneFlags())
```

`setCloneFlags` for `nocgo` is `cmd.SysProcAttr.Cloneflags = flags`
(`purego_nocgo.go:23-28`). `Namespaces.CloneFlags()` returns a flag for every
namespace whose `Path == ""` (`libcontainer/configs/namespaces_syscall.go:24-32`)
— which is all of them in the *container's* config. So an exec child is cloned
into brand-new net/ipc/uts/pid/cgroup namespaces rather than keeping the host
set and letting the Go code `setns` into the container's. For PID that means a
*fresh* PID namespace. This is masked by A today, but it is wrong, and with
`CLONE_NEWPID` the child is PID 1 of a namespace the container does not know
about.

**D. The PID namespace is skipped for exec.** In the `nocgo` child,
`joinNamespaces` refuses `NEWUSER` outright and, for `NEWPID`, refuses when
`it != initSetns` but *warns and continues* when it is:

```go
// libcontainer/join_namespaces_nocgo.go:51-63
case configs.NsName(configs.NEWUSER):
    return fmt.Errorf("joining a user namespace by path is not supported without cgo (%s)", path)
case configs.NsName(configs.NEWPID):
    if it != initSetns {
        return fmt.Errorf("joining a PID namespace by path is not supported without cgo (%s)", path)
    }
    logrus.Warnf("not joining PID namespace %s: not supported without cgo", path)
    continue
```

Because the child fails at `init_linux.go:240`, it never reaches
`joinNamespaces` at `init_linux.go:248`, so the warning is never printed. D is
the real, documented limitation; it is not the 255.

**Inferred, not verified:** the relative ordering is certain from the code, but
I did not observe a child stack trace, because the error is swallowed by the
defer. I did not run the QEMU cluster; the code chain above terminates at a
literal `os.Exit(255)` and there is no other `os.Exit(255)` on the child path
(`grep` finds one).

---

## 2. What the cgo path does that the Go path cannot

`nsexec.c` is one function (`nsexec()`, `nsexec.c:725`) entered as a C
constructor before the Go runtime starts. `init.go` shows the entry: the `init`
subcommand calls `libcontainer.Init()` after the constructor
(`init.go:11-15`). The stages are a `setjmp`/`longjmp` dance over `clone`
(`clone_parent`, `nsexec.c:314-323`), with `clone(child_func, ..., CLONE_PARENT | SIGCHLD, &ca)`.

`switch (setjmp(env))` at `nsexec.c:847` dispatches:

- **`runc:[0:PARENT]`** (`case STAGE_PARENT`, `nsexec.c:855`, set at `:862`).
  Clones stage 1 (`:867`), then services a sync loop: it writes the child's
  `uid_map`/`gid_map` (`:904-908`), forwards the stage-2 PID to runc as JSON
  (`:937-940`), and reaps. It exits (`exit(0)`) once both children are done.
  For `exec` there is no user namespace, so its work reduces to PID forwarding.
- **`runc:[1:CHILD]`** (`case STAGE_CHILD`, `nsexec.c:1010`, set at `:1023`).
  This is the setns stage:
  ```c
  // libcontainer/nsenter/nsexec.c:1033
  if (config.namespaces)
      join_namespaces(config.namespaces);
  ```
  `join_namespaces` (`nsexec.c:641`) opens every namespace fd first (`:648`,
  `__open_namespaces`), then joins them in two passes around the user namespace
  (`:667-669`), and verifies all were joined. `CLONE_NEWPID` is among the types
  it joins (`all_ns_types`, `nsexec.c:474`).
  It then `unshare`s any namespaces it is creating rather than joining
  (`try_unshare(config.cloneflags, ...)`, `nsexec.c:1107`), and finally **forks
  again**:
  ```c
  // libcontainer/nsenter/nsexec.c:1132
  stage2_pid = clone_parent(&env, STAGE_INIT);
  ```
  It reports that PID to stage 0 and exits.
- **`runc:[2:INIT]`** (`case STAGE_INIT`, `nsexec.c:1169`, set at `:1188`).
  `setsid`, `setuid(0)`, `setgid(0)`, `setgroups`, sends `SYNC_CHILD_FINISH`,
  closes the pipes, and **returns** (`nsexec.c:1223`). The C constructor
  returning is what lets the Go runtime boot; `startInitialization()` then runs
  in this process.

For the *setns/exec* case, the parts that matter are:

- the setns pass in stage 1 (`join_namespaces`, `nsexec.c:641-673`), and
- **the second fork at `nsexec.c:1132`, after `setns(CLONE_NEWPID)`,** which is
  what actually puts a process into the container's PID namespace; and
- the PID forwarding at `nsexec.c:1132-1150` / `:937-940`, which is how the
  parent learns the stage-2 host PID (`getChildPid`, `process_linux.go:636`).

The Go port reproduces stage 1's non-PID setns directly: the `nocgo` child
calls `joinNamespaces` at `init_linux.go:248`, which does
`unix.Setns(fd, 0)` per path (`join_namespaces_nocgo.go:69`). It reproduces
stage 2's `setuid(0)`/`setgid(0)`/capability work in `linuxSetnsInit.Init()`
(`libcontainer/setns_init_linux.go`, via `finalizeNamespace`). One stage-2 step
is *not* reproduced anywhere in the Go code: `setsid()`
(`nsexec.c:1195`). `grep -rn 'setsid' libcontainer/*.go` finds nothing, so the
`nocgo` init path has run without it, and the exec path would too; it is a
small, separate divergence rather than part of the exec failure.

**The one step with no Go equivalent is the fork at `nsexec.c:1132` — a fork
performed *after* `setns(CLONE_NEWPID)` so that the child lands in the
container's PID namespace, with the child then continuing to run the same
program.** Go cannot fork and continue running Go in the child; `os/exec`
always follows `clone` with `execve`. That is the sentence at
`join_namespaces_nocgo.go:30-32` ("There is no way to fork and keep running Go
code"), and it is true as far as a raw fork goes. It understates the options,
because a *fork followed by a re-exec of the same binary* is exactly what
`os/exec` does, and the child only has to run `linuxSetnsInit.Init()` — no Go
state has to survive the fork.

---

## 3. Why the PID namespace is the crux

### The kernel's rule

The pinned kernel (`linux/`, v7.2) is the primary evidence. `setns` ends at
per-type `->install` handlers (`kernel/nsproxy.c:569-603`). For PID:

```c
// kernel/pid_namespace.c:392-419
static int pidns_install(struct nsset *nsset, struct ns_common *ns)
{
    struct pid_namespace *active = task_active_pid_ns(current);
    struct pid_namespace *new = to_pid_ns(ns);

    if (!ns_capable(new->user_ns, CAP_SYS_ADMIN) ||
        !ns_capable(nsset->cred->user_ns, CAP_SYS_ADMIN))
        return -EPERM;

    /*
     * Only allow entering the current active pid namespace
     * or a child of the current active pid namespace.
     *
     * This is required for fork to return a usable pid value and
     * this maintains the property that processes and their
     * children can not escape their current pid namespace.
     */
    if (!pidns_is_ancestor(new, active))   // :410
        return -EINVAL;

    put_pid_ns(nsproxy->pid_ns_for_children);
    nsproxy->pid_ns_for_children = get_pid_ns(new);
    return 0;
}
```

Three facts fall out:

1. `setns(CLONE_NEWPID)` sets **`pid_ns_for_children`**, not the caller's own
   `active` namespace. The calling process does not move. Its *next child* is
   created in the target namespace. This is the whole reason `nsexec` forks.
2. The target must be the caller's active namespace or a descendant of it.
   Joining a container's namespace created by the same runc works (it is a
   child of runc's active namespace).
3. The fork's return value is computed with `pid_vnr` (`kernel/fork.c:2761`,
   `nr = pid_vnr(pid)`), i.e. the child's PID *in the caller's active
   namespace*. That is the comment at `kernel/pid_namespace.c:403-407`: the
   ancestor rule is what makes the returned PID usable. So if a runc parent
   thread does the `setns` and then forks, `cmd.Process.Pid` is the host PID
   the parent needs, even though the child is in the container's namespace.

There is **no `thread_group_empty` check in `pidns_install`**. Unlike the user
namespace, joining a PID namespace from a multithreaded Go process is
permitted by the kernel.

### Go's constraints

- `clone(2)`'s `CLONE_NEWPID` flag (`SysProcAttr.Cloneflags`) *creates* a new
  PID namespace. There is no SysProcAttr field to join an existing namespace by
  path — I checked the toolchain's `syscall.SysProcAttr`
  (`exec_linux.go:67-107`): it has `Cloneflags` and `Unshareflags`, no setns
  input. So the parent-side clone can be PID 1 of a fresh namespace (which is
  how the container *init* works today) but cannot put the exec process into
  the container's existing one.
- `setns` from Go is fine at the syscall level (`unix.Setns`), but it must be
  the *setns-then-fork* pair. A Go process is multi-threaded from startup, and
  a raw fork from Go is unsafe: only the forking thread survives, and locks the
  other threads held are left locked. So a `setns` followed by a raw `fork`
  that continues Go code is not available.
- `runtime.LockOSThread` pins a goroutine to an OS thread. It is what makes the
  setns-then-`os/exec` pair controllable: `cmd.Start()` performs its `clone`
  on the calling thread. `setnsProcess.startWithCPUAffinity`
  (`process_linux.go:215-238`) already uses exactly this pattern — a locked OS
  thread does thread-local work and then calls `p.cmd.Start()`, and it
  deliberately never unlocks, so the thread is terminated afterwards
  (`process_linux.go:231-237`).
- The user namespace is the namespace with the thread restriction:
  `kernel/user_namespace.c:1343-1359` refuses `userns_install` unless
  `thread_group_empty(current)` **and** `current->fs->users == 1`. A Go program
  can never satisfy the first, which is why `join_namespaces_nocgo.go:51-52`
  refuses `NEWUSER`.

### Can a Go helper do the PID join?

Yes, in one of two shapes:

- **Do the PID `setns` in the parent, then `os/exec`.** Because
  `pidns_install` has no threading restriction, a locked thread of the runc
  process can `setns` into the container's PID namespace, and the
  `clone`/`execve` that `os/exec` performs on that same thread creates a child
  already in that namespace. The child is the existing `runc init` setns
  process; it joins the *other* namespaces itself (or the parent can leave them
  to it). This is the smallest change and reuses the direct-child model of the
  rest of the `nocgo` port. The cost is that a namespace operation now happens
  in the runc process, which nsexec deliberately avoided, and the thread that
  did it must be discarded.
- **A re-exec helper.** The `runc init` child does `setns(CLONE_NEWPID)` itself,
  then `os/exec`s a second copy of itself (or a small helper) whose child lands
  in the PID namespace, and the intermediate stage exits once the grandchild is
  reported — nsexec stage 1 and stage 2 with a `setns` plus `execve` instead of
  a raw fork. It keeps all namespace work out of the runc parent, at the cost
  of a second process stage and passing the pipes/fds through it.

Both are pure Go, `CGO_ENABLED=0`, and introduce no libc.

---

## 4. Options

Every option here is in service of two different goals, and it helps to keep
them apart:

- **Unblock lifecycle hooks** (`postStart`/`preStop`). This needs `runc exec`
  to *run*, and does not, by itself, need the PID namespace.
- **Make `exec` correct.** This needs the PID namespace too, for the same
  reason the container init does: an exec'd process that is not in the
  container's PID namespace sees host processes in `/proc`, can signal them
  with the capabilities `finalizeNamespace` gives it, and is not killed with
  the container.

### (a1) Parent `setns(CLONE_NEWPID)` + `os/exec` (after fixing A/B/C)

- **Changes:** `setnsProcess` gains the container's pid path; a locked-thread
  helper opens it, calls `setns`, and `Start()`s on the same thread; the child
  stops applying clone flags (C) and the Go child already skips PID.
- **Size:** the parent-side setns is ~15 lines inside the existing
  `startWithCPUAffinity` shape; separate from the A/B/C port.
- **Risks:** doing `setns` in the runc CLI process; the locked thread must be
  discarded; the Python-style `pidns_is_ancestor` rule means this only works
  when runc's active PID namespace is an ancestor of the container's (true for
  the normal case, false if runc is itself inside a sibling namespace).
- **Static property:** preserved (pure Go, no cgo).

### (a2) A Go re-exec helper stage

- **Changes:** the `runc init` child does the non-PID setns (as today) and,
  instead of being the final process, `os/exec`s a second stage that inherits
  the PID namespace from the child's post-`setns` `pid_ns_for_children`; the
  intermediate reports the grandchild's PID and exits. The parent's
  `execSetns` then has real cgo-shaped work to do, or the direct-child model
  can carry it.
- **Size:** the largest of the Go options — a marker env var, fd/pipes passed
  through two stages, and an exit-status passthrough. It is nsexec's
  stage1/stage2 again with an `execve` in the middle.
- **Risks:** more moving parts and more ways to get the sync protocol wrong;
  but it keeps namespace work in the child and is the closest analogue of what
  already works.
- **Static property:** preserved.

### (b) A tiny cgo helper for the exec path only

- **Changes:** ship a small C (or cgo) program that does nsexec's setns+fork,
  and have runc exec delegate to it.
- **Cost:** the image deliberately has no libc, and the property the project
  depends on is that every binary is `CGO_ENABLED=0` / static
(`../k4s/DIT:125-135`).
  A cgo helper needs libc at runtime unless statically linked (musl/glibc
  static), and the build would need a C toolchain and musl in the image build.
  It also splits the runtime into two linkage models.
- **Risks:** reintroduces exactly the thing the fork removed, and the helper
  must still be kept in sync with runc's sync protocol.
- **Static property:** broken for that helper.

### (c) An external `nsenter(1)`-style helper in the image

- **Changes:** add an nsenter-like binary to the initramfs and have the exec
  path exec through it. u-root currently ships `unshare` but **no** `nsenter`
  (`../k4s/u-root/cmds/core/`), and util-linux `nsenter(1)` is not in the image and
  would need libc. So this is "write a helper", the same work as (a2), plus
  packaging it and wiring runc to call it.
- **Risks:** if the helper only does setns and then execs the user command,
  it is not enough: runc's `finalizeNamespace`, seccomp, capabilities, console
  and sync protocol must still run in the right namespaces. In practice the
  helper has to exec `runc init`, not the user command, which makes it an
  out-of-process version of (a2).
- **Static property:** if written in Go, preserved; if util-linux, broken.

### (d) Accept skipping the PID namespace for `exec`

- **Changes:** none beyond A/B/C. This is what `join_namespaces_nocgo.go:53-63`
  already intends.
- **What actually breaks:** the exec'd process (and therefore any lifecycle
  hook) runs in the host PID namespace. It can see host processes in `/proc`;
  with the container's capabilities it can signal them; it is not killed with
  the container; anything that reads `/proc` expecting the container's
  processes (for example a hook that counts them, or `ps`) sees the host's. The
  Cilium hook is `iptables-save | grep` and would not care; a generic hook that
  does `kill -TERM 1` would hit the host's PID 1.
- **Size:** the same ~10-line A/B/C port; no PID work.
- **Risks:** a security property silently lost, in a node whose whole design
  is otherwise strict (RAM-only, seccomp enforced, no network egress).
- **Static property:** preserved.

### Recommendation

**What was actually done is (a2) with the wait model from step 1, and it is
written up in section 6.** The two steps below are kept as the study wrote
them.

Do it in two steps, and keep them separable, because the first is small and
unblocks the actual pain:

1. **Port the `initProcess` `puregoNamespaces` branch to `setnsProcess`.** That
   is A, B and C together: skip the bootstrap copy, take `p.cmd.Process.Pid`
   directly instead of `execSetns`'s wait+pid decode, set `p.process.ops = p`,
   and stop applying clone flags to the exec cmd. This is roughly the same
   diff that `initProcess.start` already received (`process_linux.go:848-876`),
   and it makes `runc exec` succeed with the PID namespace skipped. Lifecycle
   hooks start working here.
2. **Then add the PID join**, and I would start with (a1): it is the smallest
   change that keeps everything `CGO_ENABLED=0`, it reuses the direct-child
   model, and the setns-then-`os/exec`-on-a-locked-thread shape already exists
   in `startWithCPUAffinity`. If testing shows the parent-side setns is too
   subtle to trust, (a2) is the fallback and is closer to nsexec, at the cost
   of a second process stage.

I would not do (b) or (c): they buy the same result as a Go re-exec at the
price of abandoning the project's one-linkage-model property for the runtime,
which is a much larger commitment than the problem warrants. (d) is a legitimate
stopgap and should be documented as a known limitation if step 2 is deferred,
but it should not be the resting state for a GPU node that intends to run
untrusted workloads.

---

## 5. Testability

**What exists, and why it cannot run here.** `tests/integration/exec.bats` is
the real coverage: `:13` (`runc exec`), `:23` (exit codes), `:43`/`:58`
(`--pid-file`), `:203` and `:254` (sub-cgroups), `:359` (`execve` error). It
drives `runc exec` against a running container, so it needs root, a working
container, and (for the cgroup cases) a specific cgroup layout. None of that is
available in this study: `sudo` needs a password. Those tests also exercise the
cgo path by default; there is no `CGO_ENABLED=0` variant.

`libcontainer/nsenter/nsenter_test.go` tests `nsexec` directly, including a
`pid:/proc/<pid>/ns/pid` join (`:19-21`), and depends on the constructor, so it
is a cgo test and does not exercise the `nocgo` port at all. `libcontainer/`
unit tests (`ls libcontainer/*_test.go`) have no setns/exec coverage.

The one nocgo precedent worth copying is the seccomp path:
`libcontainer/seccomp/seccomp_nocgo_test.go` is `//go:build linux && !cgo` and
re-execs the test binary as a helper so the filter is not installed in the test
process. **That shape is what `libcontainer/purego_nocgo_test.go` uses**, and it
needs no root: it covers the conventions the helper depends on — its argv layout
(including that the exec'd init keeps runc's argv[0]), the init path and report
descriptor it is given, that the PID path is removed from the init stage's list —
and that a report the parent cannot adopt still kills the process the helper
created. It does not perform a real setns; that still needs the guest.

**What a minimal in-guest check looks like.** The node has the built runc and
containerd, and the harness already ssh's into it
(`../k4s/scripts/guest-check.sh`, `../k4s/scripts/test-cluster.sh`). The most faithful check is exactly the failing
case, expressed as a pod:

- add an `../k4s/examples/hook-pod.yaml` with a `postStart` that writes a marker, and
  assert the pod reaches `Running` and the marker exists (the existing smoke
  pod already asserts `K4S_POD_OK` and `Seccomp: 2`, so the harness already
  knows how to read evidence out of a running container);
- optionally, a second check that the exec'd process sees the container's PID
  namespace: have the hook write `readlink /proc/self/ns/pid` and compare it
  with the container init's, or write `$$` and assert it is not a host PID.

That single hook pod is both the regression test for A/B/C and the acceptance
test for the PID work: with step 1 only, the pod passes but the namespace check
fails; with step 2, both pass. That is the check that was used:
`../k4s/examples/hook-pod.yaml` was added and is asserted on both boots. The strip is
gone, so `make test-cluster-cni` with no knob now runs Cilium's real
`postStart`/`preStop` as well, and that run passes too (`cilium: ok`,
`hook: ok` on both boots).

I did not run the QEMU cluster for this study. The failure path is pinned by
code that ends in a single literal `os.Exit(255)` and a single wrapper string
that matches the captured kubelet error; the only thing a run would add is
confirmation of the swallowed child message, and that message is already known
here (`invalid character '\x10' looking for beginning of value`).

---

## The claim in `docs/nsenter-and-runc.md`, checked

> A user namespace cannot be joined this way at all (`userns_install()` refuses
> unless the caller's thread group is empty), and a PID namespace needs the fork
> nsexec performs so that the child becomes PID 1. Those two are refused for a
> container init; for `runc exec` the PID namespace is skipped with a warning.

- **User namespace, verified.** `userns_install` at
  `linux/kernel/user_namespace.c:1343` returns `-EINVAL` at `:1355` when
  `!thread_group_empty(current)` and at `:1358` when `current->fs->users != 1`.
  Go satisfies neither. `join_namespaces_nocgo.go:51-52` refuses it.
- **PID needs a fork, verified.** `pidns_install`
  (`linux/kernel/pid_namespace.c:392`) only sets `pid_ns_for_children`; the
  caller does not move. `nsexec` forks at `nsexec.c:1132` after joining.
- **"refused for a container init", verified.** `join_namespaces_nocgo.go:54-55`
  returns an error for `NEWPID` when `it != initSetns`.
- **"for `runc exec` the PID namespace is skipped with a warning", true of the
  function but misleading as an explanation.** `join_namespaces_nocgo.go:62`
  does warn and `continue`. But the child never reaches `joinNamespaces`: it
  returns at `init_linux.go:240`, before the call at `init_linux.go:248`, and
  the warning is not printed in the observed failure. The 255 is caused by the
  netlink bootstrap message on the init pipe, not by the PID refusal.
- The rest of the same doc's bullet is now **stale and contradicted by the
  code**: it says "the refusal above applies to `exec` too, not only to a
  container init" and "a PID namespace needs the fork nsexec performs -- the
  child has to become PID 1 -- so the refusal above applies to `exec` too".
  The commit "libcontainer: join namespaces given by path without cgo"
  (`purego-exec`) changed `NEWPID` to be refused only for `initStandard` and skipped for
  `initSetns`. The bullet should be rewritten.

Put more simply: the doc's *first* sentence describes the code correctly, and
its *last* inference about why `exec` fails is wrong. The fork's own latest
commit made the skip explicit; the failure predates and is independent of it.

---

## Verified, inferred, unknown

**Verified in code (this checkout):** the whole error chain from
`exec.go:114` to `init_linux.go:129`; the unconditional bootstrap copy at
`process_linux.go:481-485`; the unconditional `setCloneFlags` at
`container_linux.go:565`; `execSetns`'s wait+pid decode at
`process_linux.go:598-628`; the child's JSON decode at `init_linux.go:240` and
the defer that clears the return at `init_linux.go:148-162`; the `NEWUSER` /
`NEWPID` handling in `join_namespaces_nocgo.go`; the `nr = pid_vnr(pid)` return
at `kernel/fork.c:2761`; and the kernel install handlers quoted above.

**Inferred:** that the child's decode error is exactly the `0x10` byte of the
netlink header (confirmed against a standalone reproduction of the serialized
header, but not against the running guest); and that A+B+C can be fixed
independently of the PID namespace.

**Unknown / not verified:** whether the parent-side `setns(CLONE_NEWPID)` +
`os/exec` approach survives Go's runtime and scheduler in practice on the node
(it is consistent with the kernel and with `startWithCPUAffinity`'s existing
pattern, but I could not build a rootless repro to run it); whether
`linuxSetnsInit` behaves identically when it is the direct `nocgo` child rather
than nsexec stage 2 (the seccomp ordering is the same, and neither path calls
`setsid`, but it has not been run); and whether the rootfs-level
hook semantics (e.g. `postStart` needing the container's mount namespace before
it is fully set up) add a constraint beyond the PID namespace.

---

## 6. Implemented: option (a2), the fork's `runcns` subcommand

This is what was built, and it is the study's (a2) with the wait model from the
study's step 1 and three corrections the option sketch did not contain: the
`CLONE_PARENT` clone, and the two things joining a mount namespace from Go needs
(`unshare(CLONE_FS)`, and opening every namespace fd before joining any). Line
numbers below are the post-implementation tree.

### The shape

`setns(CLONE_NEWPID)` cannot put the caller into a PID namespace (§3), and
`execve` creates no process, so the sequence cannot be "setns, then exec the
next stage". It has to be **setns, then create a process, and the created
process is the next stage** — which is nsexec's stage 1 and stage 2 with an
`execve` where nsexec has its second, raw fork.

    runc exec
      └─ runc runcns <pid-ns-path> <runc> <runc-argv0> init   (direct child)
           ├─ setns(CLONE_NEWPID, <pid-ns-path>)  -- arms pid_ns_for_children
           ├─ clone+execve  -->  runc init        (runc's child, container pidns;
           │                                        argv[0] is <runc-argv0>)
           ├─ write that pid to the report pipe
           └─ exit 0

    runc exec (parent)
      ├─ reads the pid from the report pipe
      ├─ reaps the runcns stage
      └─ adopts the pid: p.cmd.Process = FindProcess(pid), p.process.ops = p

Three pieces:

1. **`libcontainer/runcns_linux.go`**, in the fork — the stage itself,
   `CGO_ENABLED=0`, a subcommand of the `runc` binary rather than a second
   binary. `runRuncNs` (`:118` locks the OS thread, `:124` does the `setns`);
   `startExecNsStage` (`:134`) starts the next stage with
   `SysProcAttr.Cloneflags = CLONE_PARENT` (`:167`) and writes
   `cmd.Process.Pid` to the descriptor named by `runcNsReportFdEnv` (`:180`).
   It hands the child `argv[1:]` as its argv, whose argv[0] is the runc argv[0]
   passed in — not the descriptor path it execs. `RunRuncNs` (`:46`) is the
   entry point, and it never returns, like `Init`.

2. **The runc fork**, `libcontainer/`:

   - `purego_nocgo.go:65` `stageExecNs` rewrites the exec command: it takes the
     PID path out of the init stage's namespace list, appends one report pipe to
     `cmd.ExtraFiles`, and invokes the stage as `os.Executable()` plus
     `runcns <pid-ns-path> <runc> <runc-argv0> init` (`:74`, `:87`, `:103`),
     returning the parent end of the pipe. `purego_cgo.go` has the no-op
     version, so the cgo path is untouched.
   - `container_linux.go:732` calls it from `newSetnsProcess`, and
     `container_linux.go:572` is the fix for defect C. The netlink bootstrap
     payload is now built only under cgo (`:671`, `:717`), because nothing reads
     it without the C constructor.
   - `process_linux.go:630` `execSetns` branches: with a report pipe it calls
     `adoptRuncNsChild` (`:689`), which replaces the study's
     "wait for the direct child, then decode stage1/stage2 JSON" (`:598-628`
     before the change) with a read of the reported pid; with no report pipe in
     the `!cgo` build it takes `p.cmd.Process.Pid` as `initProcess.start`
     already did; otherwise it is the cgo path, unchanged.
   - `process_linux.go:513` is the fix for defect A.
   - `join_namespaces_nocgo.go:69` `joinNamespaces` now opens every namespace
     fd before joining any (`:112`, `:115`), and calls `detachFs` (`:148`) before
     a mount join. Its PID-path branch (`:95`) still skips rather than refuses,
     but now says why, and points at the stage.

3. **Dispatch and packaging**: there is no separate binary to package. The stage
   is dispatched before the CLI, next to `init` (`init.go:17`), so it is absent
   from `runc --help`, takes no flags, and runs before `app.Before`. Nothing in
   `../k4s/go.work`, `../k4s/DIT` or the image changes for it: it is inside
   `../k4s/build/runc`, which `../k4s/DIT` already ships as a `-files` binary at
   `/bin/runc`.

The stage used to be a helper binary in the k4s repository — `cmd/runc-ns`,
packaged as a `bb` applet at `/bbin/runc-ns`, found on `PATH`, with `RUNC_NS` as
an override. **It was moved into the fork because the thing it stages is runc
itself.** `runc init` is already a re-exec of `/proc/self/exe`, and nsexec lives
inside the runc binary too, so a Go stage in the same binary is the closer
analogue of both; the stage and the runc that invokes it can never be different
versions; and the report-fd name went from two independent string literals, one
per repository, to one definition. The `PATH` lookup and the `RUNC_NS` override
are gone with it, so there is nothing to test for either.

### The correction: `CLONE_PARENT` is required

The option sketch said "runc's direct child is now the staging process, which exits
immediately, while the process runc actually needs a PID for is the
grandchild". True, but it does not say how runc is to *reap* the grandchild, and
without that `runc exec` does not work at all: `runc`'s non-detached path waits
for the exec'd process to exit through a SIGCHLD loop that is a `wait4(-1)` over
**its own children** (`signals.go`, `reap`), and reports the status of the pid
it recorded in `forward`. A grandchild whose parent is the `runcns` stage —
which has exited — is reparented, is nobody's child of runc's, and would never be
reported: `runc exec` would hang forever instead of exiting with the hook's
status.

So the stage starts the next stage with `CLONE_PARENT`, exactly as nsexec's
`clone_parent()` does (`nsexec.c:322`, and the comment at `nsexec.c:930-935`
explains that runc has to reap stage 1 *for* stage 0 because of it). The
grandchild is then runc's own child: `p.cmd.Wait()` reaps it, `cmd.Wait()`
returns its status, and the SIGCHLD loop sees it.

Two smaller consequences of the same fact, both good:

- `pidfd_getfd` on the exec'd process (`pidGetFd`, used by the seccomp listener
  sync) needs `PTRACE_MODE_ATTACH_REALCREDS` to succeed. `runc` is root and has
  `CAP_SYS_PTRACE`, so it would pass either way, but under `ptrace_scope=1` a
  non-descendant would not, and with `CLONE_PARENT` the grandchild is a direct
  descendant.
- The stage must not `Wait()` for the grandchild: it is not its child any more.
  It writes the pid and exits, and the zombie is runc's to collect.

### A fourth defect the study did not find: joining a mount namespace from Go

The study said "network, ipc and uts ... have no thread-group restriction, and
neither do mount and cgroup". That is true of cgroup and **false of mount**, and
correcting it is part of this work.

The first run after A, B and C were fixed got exactly as far as `runc init`
joining the container's namespaces, and failed there:

```
OCI runtime exec failed: exec failed: unable to start container process:
setns into mnt namespace /proc/7954/ns/mnt: invalid argument
```

`EINVAL` from `mntns_install` (`fs/namespace.c:6496`) is this:

```c
	if (fs->users != 1)
		return -EINVAL;
```

A mount namespace is the one type whose install handler refuses a caller whose
`fs_struct` is shared, and the reason is `prepare_nsset`
(`kernel/nsproxy.c:369-376`):

```c
	/* Only create a temporary copy of fs_struct if we really need to. */
	if (flags == CLONE_NEWNS) {
		nsset->fs = me->fs;
	} else if (flags & CLONE_NEWNS) {
		nsset->fs = copy_fs_struct(me->fs);
```

A `setns` of a mount namespace on its own rewrites the caller's **own** `fs` -
root and working directory - which is only sound if nothing else is using it.
(`setns(fd, 0)` resolves to `flags = ns->ns_type`, i.e. exactly `CLONE_NEWNS`,
so it takes the first branch.) Every thread of a Go process shares one
`fs_struct`, because the runtime creates threads with `CLONE_FS`
(`runtime/os_linux.go`: `_CLONE_FS | /* share cwd, etc */`), so by the time any
Go code runs, `fs->users` is already at least 2 and the setns always fails.

**Why this had never shown.** The container's own init does not join a mount
namespace: `CloneFlags()` includes `CLONE_NEWNS` for it, so it is created by
`clone(2)`. The three namespaces a CRI container does join by path - net, ipc,
uts - have no such check, so they worked. And nsexec joins **every** namespace,
mount included, in stage 1, before the Go runtime exists: a process created by
`clone(child_func, ..., CLONE_PARENT|SIGCHLD, ...)` that has not started Go yet
is single-threaded, so `fs->users == 1` and the same setns succeeds there. This
is the fourth thing the `!cgo` port had not reproduced, and `runc exec` is the
first caller to need it: it is the only path with a mount namespace in its list.

The fix is `detachFs` (`join_namespaces_nocgo.go`), called before the mount
`setns`: `unshare(CLONE_FS)`, which gives the calling task a copy of the
`fs_struct` with `users == 1` and drops it from the shared one. It is not
invented here - `goCreateMountSources` (`process_linux.go`) already does exactly
this pair, on its own locked thread, with the comment "Detach from the shared fs
of the rest of the Go process in order to be able to CLONE_NEWNS". It has to be
the thread `Init` locked, because that is the thread whose `fs` the mount
namespace install then rewrites and which goes on to exec the container
process; the runtime's other threads keep the `fs_struct` they had. The kernel
returns without doing anything if the fs is already unshared, so it is
idempotent.

**And every descriptor has to be opened before any of them is joined,** which is
the second half of the same lesson and the second failure of that run:

```
OCI runtime exec failed: exec failed: unable to start container process:
open cgroup namespace /proc/7409/ns/cgroup: no such file or directory
```

The join order is `NamespaceTypes`: ipc, uts, net, ..., mnt, cgroup. A namespace
path is `/proc/<host pid>/ns/<type>`, and once the mount namespace has been
joined, `/proc` is the container's procfs — a procfs for the container's own PID
namespace, in which the host pid the *next* path names does not exist. So the
cgroup open fails with `ENOENT` immediately after a successful mount join (and
it would fail for any path that came after `mnt`).

nsexec has the same shape and the same fix, with the reason in a comment
(`nsexec.c:646-650`):

```c
	/*
	 * We have to open the file descriptors first, since after we join the
	 * mnt or user namespaces we might no longer be able to access the
	 * paths.
	 */
	to_join = __open_namespaces(nsspec, &ns_list, &ns_len);
```

`joinNamespaces` now does the same in two passes: it opens every fd (and applies
the user/PID policy) first, then joins them. This is exactly the kind of thing
the single file's worth of Go that did not reproduce nsexec left out, and it
only shows up on the one path that joins a mount namespace.

### A and C are still needed; B is replaced; the stage subsumes neither

**A — the netlink bootstrap copy — is still required**, and the stage does not
subsume it. A is about what the *parent* writes on the init pipe. The stage
does not read that pipe; it passes it through untouched, so `runc init` still
reads it directly, and the bootstrap message still has to not be written.
`process_linux.go:513` now guards the copy with `!puregoNamespaces`, following
`initProcess.start`'s precedent.

**C — `setCloneFlags` on an exec child — is still required**, and is in fact
more visible now. `container_linux.go:572` only calls it when `p.Init`. If it
were left unguarded, the direct child would be the `runcns` stage cloned into a
*fresh* PID namespace and a fresh set of every other namespace (in the cgo build
`setCloneFlags` is a no-op, which is why this never showed): it would
then be PID 1 of a namespace of its own, and its `setns` into the container's
would fail with `EINVAL` from `pidns_install`, because the container's namespace
is not a descendant of its own. It is not merely wrong, it stops the mechanism
dead.

**B — `execSetns`'s wait-for-the-direct-child-then-decode-JSON — is replaced,
not fixed.** The stage reports one integer on a pipe of its own, so both halves
of the cgo model go away: there is no stage 0 to wait for (the stage is reaped
explicitly in `adoptRuncNsChild` so the wait that follows is aimed at the right
process) and no `{"stage1_pid":…,"stage2_pid":…}` to decode. Writing that JSON
on the *init* pipe was considered and rejected: in the cgo build the parent
happens to read it before stage 2 boots Go and reads the same pipe, which is a
benign race there, and there is no reason to reproduce it.

### What was verified, and how

**In the guest, end to end.** `make test-cluster-cni` (Cilium, two boots,
the 6144 MiB node) now passes with `cluster: ok`, and on both boots it prints:

```
hook: ok (postStart ran, in the container's PID namespace)
```

which is `check_marker` asserting three things from evidence the node wrote to a
hostPath: `K4S_HOOK_OK` is in the hook's marker file, and
`/var/log/k4s-hook/hook-ns` and `/var/log/k4s-hook/init-ns` are both
`pid:[4026532138]` — the same PID-namespace inode for the process `runc exec`
started and for the container's own init. The hook is a `postStart`, which
kubelet runs through CRI `ExecSync`, i.e. `runc exec`; before this work it
failed outright, kubelet killed the container, and the pod crash-looped.

Two intermediate runs are what got there, and both are useful as evidence:

- With A, B and C fixed and the stage written exactly as described above, the
exec reached `runc init`'s `joinNamespaces` and failed on the **mount** setns
with `EINVAL`. That verified the whole staging mechanism — the PID path was
resolved, `pid_ns_for_children` armed, `runc init` started as runc's own child,
its host pid reported, the parent adopted it and wrote the initConfig, and
`runc init` read it and began joining namespaces — and left only namespace
joining wrong.
- With that fixed, the mount join succeeded and the **cgroup** open failed with
`ENOENT`, which is the open-order defect above.

**On the host**, where the mechanisms that need no privileges can be tested
directly:

- **`os/exec` accepts `Cloneflags: CLONE_PARENT`**, alongside the
  `CLONE_VFORK|CLONE_VM` Go adds itself (the syscall layer adds `CLONE_PIDFD`
  only when `SysProcAttr.PidFD != nil`, which it is not here, and puts `SIGCHLD`
  in the low byte of the flags), and the process it creates
  really is the *grandparent's* child. A throwaway three-process program
  confirmed `getppid()` of the grandchild is the grandparent's pid, not the
  middle process's, and that the grandparent's `Wait()` on it returned its exit
  status (7) — which only happens for a real child. This is the load-bearing
  assumption of the whole design, and the guest run then confirmed it in place.
- **Descriptors survive the extra exec at the same numbers.** A program that
  passed a pipe as `ExtraFiles` (fd 3, named by an environment variable, exactly
  as `_LIBCONTAINER_INITPIPE` names it) and an intermediate process that listed
  nothing of its own had both the middle and the final process write to fd 3
  successfully. That is what makes "no fd re-plumbing" in the stage true rather
  than hopeful; Go's `forkAndExecInChild1` only shuffles the fds it is given and
  leaves higher ones to `close-on-exec`, which `ExtraFiles` clears.
- **The kernel's rules**, in the pinned checkout: `pidns_install`
  (`kernel/pid_namespace.c:392`) sets `pid_ns_for_children` only;
  `pidns_is_ancestor(new, active)` means "`active` is an ancestor of `new`", so
  the container's namespace must be a descendant of runc's (it is);
  `nr = pid_vnr(pid)` (`kernel/fork.c:2761`) is the number in the caller's
  namespace, i.e. the host pid runc needs; and `copy_namespaces`
  (`kernel/nsproxy.c:169-181`) *shares* the nsproxy when `CLONE_VM` is set and
  no `CLONE_NEW*` flag is, which is exactly the clone `os/exec` performs, so the
  child is created in the armed namespace.

**By building and testing:** `CGO_ENABLED=0` and `CGO_ENABLED=1` builds of the
fork and `go vet` for both — the `runcns` subcommand is present in both, though
only the `!cgo` build stages an exec through it. (`go vet ./...` under
`CGO_ENABLED=0` fails in `libcontainer/nsenter/test`, whose `escape.go` imports
`"C"`; that is upstream and predates this work.) And `make image`, which no
longer builds or packages a `bb` applet for the stage: it is inside
`../k4s/build/runc`, and `cpio -itv < ../k4s/initramfs.cpio` has no `runc-ns`
entry.
`libcontainer/purego_nocgo_test.go` runs under `CGO_ENABLED=0` and needs no root:
it covers the argument, descriptor and report-pipe conventions, and, added when
the stage moved into the fork, the exec half of it — that the child is started
with the caller's argv0 rather than the path it was exec'd from, and that
`CLONE_PARENT` makes it the caller's *parent's* child, which is the property the
reap depends on. It does not perform a real setns.

### What is still not covered, and what is most likely to be wrong

- **No exec shape except a plain `runc exec` of a short command has been run.**
  That covers the hook case, which is the point, but not: a nonzero exit status
  coming back out of `runc exec` (the hook exits 0; the *wait* is exercised,
  because kubelet would have hung otherwise, but status propagation of a
  non-zero code is not), `--detach`, `--preserve-fds`, or a console socket
  (`kubectl exec -it`).
- **The no-PID-namespace branch has not been run.** A container whose config has
  no PID namespace skips the stage entirely and takes the direct-child model; a
  CRI container always has one, so this is the hand-written-bundle case.
- **The `ParentDeathSignal` divergence.** `cmd.SysProcAttr.Pdeathsig` is still
  set on the direct child, which is now the `runcns` stage: it would be delivered
  to a process that exits immediately, and it is cleared for children by
  `copy_process`, so an exec runs without it. This is invisible for CRI
  containers (containerd does not set it), but it is a real divergence if
  anything ever does.
- **`setsid` is still not called**, which the study already noted is a
  pre-existing divergence from nsexec stage 2 rather than part of this work.
- **User namespaces are still refused**, by `joinNamespaces`, and the stage
  does not change that.
- **The review fixes have fork-side unit tests, but they are not the guest.**
  `libcontainer/purego_nocgo_test.go` covers the stage wiring and the leak fixed
  after review — a report `adoptRuncNsChild` cannot adopt must kill the process
  the stage created. The `Wait()`-failure arm of the same leak is covered by the
  same deferred kill but is not separately provoked, and the test does not perform
  a real setns. The in-guest evidence remains the hook pod above.
- **The stage is located with `os.Executable()`, which is inferred to have one
  gap.** It is `readlink /proc/self/exe`, so it is absolute and never goes
  through `PATH`, which is the point. But if runc is itself already running from
  a cloned binary (`exeseal.IsSelfExeCloned()`), `/proc/self/exe` is a
  `memfd:` link and `os.Executable()` names something that cannot be exec'd;
  `newParentProcess` handles exactly that case for `runc init` by using
  `/proc/self/exe` directly. It is not reachable from `runc exec` as containerd
  invokes it (the on-disk binary), so it has not been exercised, and it has not
  been reproduced: the gap is read out of Go's `os.Executable` and the memfd
  semantics, not observed.
- The most likely thing still to be wrong is one of those exec shapes: the stage
  passes the console socket and any preserved descriptors through by
  inheritance, which the host experiment says works, but nothing has actually
  run an exec that has one. After that, `detachFs` is the change with the widest
  reach it has not been tested for: it is skipped entirely for the container
  init in every configuration this project uses (there is never a mount
  namespace in its path list), but a bundle that asks a container init to join
  a mount namespace by path would now get past the setns and could fail later in
  `pivotRoot`, which resolves `config.Rootfs` as an absolute host path.
