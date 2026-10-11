//go:build linux && amd64

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"strings"
	"syscall"
	"unsafe"
	"time"

	"golang.org/x/sys/unix"

	"github.com/opencontainers/runc/libcontainer/seccomp"
)

// ---------------------------------------------------------------------------
// The result channel.
//
// A filtered process cannot be trusted to write() its own results: the very
// syscall under test may be blocked, and so may write itself. So the child
// stores its observation into a shared memory page -- a plain store, no syscall
// -- and then terminates with an INT3, which is a trap and not a syscall, so
// seccomp cannot intervene. The parent reads the page whatever the child's exit
// status was. That makes the protocol immune to blocked exit_group, KILL
// actions and TRAPs, and it means no probe has to wait for a timeout to learn
// what happened.
// ---------------------------------------------------------------------------

const (
	offR1     = 0
	offR2     = 8
	offErrno  = 16 // uint64, errno or -1 when the syscall returned 0
	offFlags  = 24 // uint8
	offErrLen = 25 // uint8
	offErrMsg = 32
	offStage  = 27 // how far the child got, written with plain stores
	offCase   = 256 // the child's own copy of the case name, for alignment
	caseLen   = 40
	resPage   = 4096
)

const (
	flagResult   = 1 << 0 // the probe ran and its errno is in offErrno
	flagSurvivor = 1 << 4 // a second thread outlived the probe thread
)

func storeError(page []byte, flags byte, msg string) {
	if len(msg) > 200 {
		msg = msg[:200]
	}
	page[offErrLen] = byte(len(msg))
	copy(page[offErrMsg:offErrMsg+len(msg)], msg)
	page[offFlags] |= flags
}

const (
	flagInstallErr = 1 << 2
	flagSetupErr   = 1 << 3
)

// ---------------------------------------------------------------------------

// consolef writes straight to the console: the only channel that works no
// matter how the orchestrator has wired a child's stdout and stderr.
func consolef(format string, args ...any) {
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	fmt.Fprintf(f, format, args...)
	f.Close()
}

func main() {
	if os.Getenv("VMDIFF_PROGRESS") != "" {
		consolef("TRACE main argv=%q pid=%d\n", os.Args, os.Getpid())
	}
	if len(os.Args) < 2 {
		// The kernel runs /init with no arguments, so that is the orchestrator.
		cmdInit()
		return
	}
	switch os.Args[1] {
	case "--list":
		for _, n := range caseNames() {
			fmt.Println(n)
		}
	case "--probe":
		cmdProbe(os.Args[2:])
	case "--run":
		cmdRun()
	case "--init":
		cmdInit()
	default:
		fmt.Fprintf(os.Stderr, "vmdiff: unknown mode %q\n", os.Args[1])
		os.Exit(2)
	}
}

// cmdProbe is the child: install one filter, run one probe, store the result.
// Its argv is "--probe <caseIndex> <probeIndex>", and it inherits the result
// page as file descriptor 3. A case index of -1 means "no filter", which is how
// the unfiltered baseline is measured.
func cmdProbe(args []string) {
	if len(args) != 2 {
		die("--probe wants <caseIndex> <probeIndex>")
	}
	caseIdx, err := strconv.Atoi(args[0])
	if err != nil {
		die("case index: %v", err)
	}
	probeIdx, err := strconv.Atoi(args[1])
	if err != nil {
		die("probe index: %v", err)
	}
	if probeIdx < 0 || probeIdx >= len(probes) {
		die("probe index %d out of range", probeIdx)
	}

	// The filter is installed per-thread (prctl, and seccomp(2) without
	// TSYNC), so the probe has to run on the thread that installed it. Without
	// this, the goroutine can be handed off during the install syscall and
	// resume on another thread, which is then unfiltered -- which showed up as
	// a rare "the filter let everything through" result.
	runtime.LockOSThread()

	page, err := unix.Mmap(3, 0, resPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		die("mmap result page: %v", err)
	}
	defer unix.Munmap(page)

	p := probes[probeIdx]

	// Everything the probe needs is computed before the filter exists. After
	// the install returns, the only work left is a store and a call into
	// assembly: a closure call, an allocation, a goroutine spawn or a stack
	// growth there would need a syscall, the filter may deny it, and the Go
	// runtime answers a denied syscall by killing the process before the probe
	// ever runs. That is not hypothetical -- it is what the stage markers in
	// the result page were added to find.
	if p.Setup != nil {
		if err := p.Setup(); err != nil {
			storeError(page, flagSetupErr, err.Error())
			finish()
		}
	}
	nr := p.Nr()
	var argv [6]uintptr
	if p.Args != nil {
		argv = p.Args()
	}
	abi := uintptr(0)
	if p.Abi == AbiI386 {
		abi = 1
	}

	// The survivor goroutine is started here too, before the filter: starting a
	// goroutine can need a new OS thread, and clone(2) is a syscall.
	if p.Survivor {
		startSurvivor(page)
	}

	req := probeRequest{page: page, abi: abi, nr: nr, argv: argv}

	if caseIdx >= 0 {
		cs := cases()
		if caseIdx >= len(cs) {
			die("case index %d out of range", caseIdx)
		}
		// The child records which profile it is about to install, so the
		// parent can prove the two builds measured the same case.
		copy(page[offCase:offCase+caseLen], cs[caseIdx].Name)
		page[offStage] = 1
		fd, err := seccomp.InitSeccomp(cs[caseIdx].buildConfig())
		if err != nil {
			// The filter is not installed, so writing is still safe -- but
			// store the message anyway, for uniformity.
			storeError(page, flagInstallErr, err.Error())
			finish()
		}
		_ = fd // a NEW_LISTENER descriptor, kept open until the process dies
		page[offStage] = 2
	}

	runProbe(&req)
}

// probeRequest holds everything runProbe needs, precomputed while the process
// is still unfiltered.
type probeRequest struct {
	page []byte
	abi  uintptr
	nr   uintptr
	argv [6]uintptr
}

// runProbe is nosplit and does no allocation, no closure call and no goroutine
// spawn: it must not need a syscall between the filter being installed and the
// probe syscall being issued.
//
//go:nosplit
func runProbe(r *probeRequest) {
	r.page[offStage] = 3
	probeAndStore(unsafe.Pointer(&r.page[0]), r.abi, r.nr,
		r.argv[0], r.argv[1], r.argv[2], r.argv[3], r.argv[4], r.argv[5])
}

// startSurvivor starts the second thread that outlives the probe thread when a
// KILL_THREAD action fires. It is called before the filter is installed because
// spawning a goroutine may need clone(2).
func startSurvivor(page []byte) {
	go func() {
		runtime.LockOSThread()
		// Busy-wait on the vDSO clock rather than time.Sleep, which is a
		// syscall the filter may kill.
		start := time.Now()
		for time.Since(start) < 150*time.Millisecond {
			runtime.Gosched()
		}
		page[offFlags] |= flagSurvivor
		finish()
	}()
}

// finish tries to end the process with exit_group, falling back to exit. A
// profile can block both -- they are ordinary syscalls -- so the parent does
// not wait for this to succeed: it polls the shared page, sees the result the
// moment it is stored, and SIGKILLs the child itself. Nothing here is allowed
// to be load-bearing.
func finish() {
	for {
		unix.RawSyscall(unix.SYS_EXIT_GROUP, 0, 0, 0)
		unix.RawSyscall(unix.SYS_EXIT, 0, 0, 0)
	}
}

// lastProgress is the last probe started by this process.
var lastProgress atomic.Value

// watchdog prints the last probe started every few seconds and gives up after
// the deadline, so a hang leaves a durable record on the console instead of a
// QEMU process that has to be killed (which can lose buffered serial output).
func watchdog(label string, limit time.Duration) {
	start := time.Now()
	for {
		time.Sleep(3 * time.Second)
		last, _ := lastProgress.Load().(string)
		el := time.Since(start).Round(time.Second)
		fmt.Printf("WATCHDOG %s %s last=%q\n", label, el, last)
		if time.Since(start) > limit {
			fmt.Printf("WATCHDOG %s giving up\n", label)
			poweroff(1)
		}
	}
}

// observation is one probe's outcome under one case.
// progress records the last (case, probe) started, so a hung harness can be
// located. It writes straight to /dev/console when asked, because the
// orchestrator runs --run with a captured stdout and a null stderr.
func progress(caseName, probe string) {
	lastProgress.Store(caseName + " / " + probe)
	if os.Getenv("VMDIFF_PROGRESS") == "" {
		return
	}
	consolef("PROGRESS %s / %s\n", caseName, probe)
}

type observation struct {
	result string // "errno=13", "trap", "killed(sig=31 SIGSYS)", "blocked", ...
	exit   string // how the child actually died, when that is informative
	ran    bool   // the probe syscall was issued, so the result is evidence
	dur    time.Duration
}

func (o observation) String() string { return o.result }

// runChild runs one (case, probe) pair and returns what happened.
//
// The child stores its observation into the shared page and only then tries to
// exit, so the parent watches the page and kills the child as soon as the
// answer appears. That is what makes a filter which blocks exit_group harmless
// here: the answer is never carried by the exit status.
// runChild runs one (case, probe) pair, retrying when the child died before
// the probe syscall could be issued. That failure mode is the Go runtime
// noticing a denied syscall of its own, not the filter deciding anything, and
// it is rare but real; a probe that never ran is not evidence.
func runChild(self, caseIdx, probeIdx, caseName string) observation {
	const attempts = 4
	var last observation
	start := time.Now()
	for attempt := 1; attempt <= attempts; attempt++ {
		last = runChildOnce(self, caseIdx, probeIdx, caseName)
		if last.ran {
			last.dur = time.Since(start)
			return last
		}
	}
	last.dur = time.Since(start)
	last.result += fmt.Sprintf(" (harness failed %d times)", attempts)
	return last
}

func runChildOnce(self, caseIdx, probeIdx, caseName string) observation {
	fd, err := unix.MemfdCreate("vmdiff", 0)
	if err != nil {
		die("memfd_create: %v", err)
	}
	page := os.NewFile(uintptr(fd), "vmdiff-result")
	defer page.Close()
	if err := page.Truncate(resPage); err != nil {
		die("truncate: %v", err)
	}
	mapped, err := unix.Mmap(fd, 0, resPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		die("parent mmap: %v", err)
	}
	defer unix.Munmap(mapped)
	for i := range mapped {
		mapped[i] = 0
	}

	var out strings.Builder
	cmd := exec.Command(self, "--probe", caseIdx, probeIdx)
	// One P and no asynchronous preemption: both cut down the number of Go
	// runtime threads that can be running when the filter lands, which is the
	// only thing that can still kill a child before its probe runs.
	// Two Ps, not one: a survivor goroutine needs a P of its own, and when the
	// probe thread is killed by KILL_THREAD it holds the one P it had, so with
	// GOMAXPROCS=1 the survivor can never run and KILL_THREAD is
	// indistinguishable from a blocked syscall.
	gmp := os.Getenv("VMDIFF_GOMAXPROCS")
	if gmp == "" {
		gmp = "2"
	}
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+gmp, "GODEBUG=asyncpreemptoff=1")
	cmd.ExtraFiles = []*os.File{page} // becomes fd 3 in the child
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		die("start probe child: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(250 * time.Millisecond)
	parentKilled, timedOut := false, false
	var runErr error
	for {
		if mapped[offFlags] != 0 {
			// The answer is in; the child may be spinning on a blocked exit.
			parentKilled = true
			_ = cmd.Process.Kill()
			runErr = <-done
			break
		}
		select {
		case runErr = <-done:
		default:
			if time.Now().After(deadline) {
				timedOut = true
				parentKilled = true
				_ = cmd.Process.Kill()
				runErr = <-done
			} else {
				time.Sleep(300 * time.Microsecond)
				continue
			}
		}
		break
	}

	exit := describeExit(cmd, runErr, timedOut, parentKilled)

	flags := mapped[offFlags]
	errno := binary.LittleEndian.Uint64(mapped[offErrno:])
	msgLen := int(mapped[offErrLen])
	msg := ""
	if msgLen > 0 && offErrMsg+msgLen <= len(mapped) {
		msg = string(mapped[offErrMsg : offErrMsg+msgLen])
	}
	childCase := strings.TrimRight(string(mapped[offCase:offCase+caseLen]), "\x00")
	if caseIdx != "-1" && childCase != caseName {
		// Should be impossible; if it happens, the report is meaningless.
		return observation{result: fmt.Sprintf("ALIGNMENT-BUG child ran %q, parent expected %q", childCase, caseName), exit: exit, ran: true}
	}
	ran := mapped[offStage] >= 4

	switch {
	case flags&flagInstallErr != 0:
		return observation{result: "install-error: " + msg, exit: exit, ran: true}
	case flags&flagSetupErr != 0:
		return observation{result: "setup-error: " + msg, exit: exit, ran: true}
	case flags&flagSurvivor != 0 && flags&flagResult == 0:
		// The probe thread died and another thread lived on: KILL_THREAD.
		return observation{result: "thread-killed (process survived)", exit: exit, ran: true}
	case flags&flagResult != 0:
		return observation{result: fmt.Sprintf("errno=%d", errno), exit: exit, ran: true}
	case !ran:
		// The child died before the probe syscall was issued: harness noise,
		// retried by runChild.
		return observation{result: fmt.Sprintf("harness-failure (stage %d)", mapped[offStage]), exit: exit}
	case timedOut:
		// The probe syscall was issued and never returned: the thread was
		// killed by a KILL action (the rest of the Go process stays alive) or
		// the syscall is blocked by a NOTIFY filter with no listener. The
		// survivor probes tell those apart.
		return observation{result: "no-result (killed or blocked)", exit: exit, ran: true}
	case parentKilled:
		// The probe thread was killed (a KILL action) or the syscall blocked;
		// the survivor probes tell those apart.
		return observation{result: "no-result (thread died or blocked)" + childNoise(out.String()), exit: exit, ran: true}
	default:
		return observation{result: "killed " + exit + childNoise(out.String()), exit: exit, ran: true}
	}
}

// childNoise surfaces whatever the child wrote before dying, which is how a Go
// runtime throw (it writes a traceback and calls breakpoint) is told apart from
// a filter action.
var logrusTimestamp = regexp.MustCompile(`time="[^"]*" `)

func childNoise(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Drop the logrus timestamp, which would otherwise make every diff noisy.
	s = logrusTimestamp.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\n", " | ")
	if len(s) > 700 {
		s = s[:700]
	}
	return " [" + s + "]"
}

func describeExit(cmd *exec.Cmd, runErr error, timedOut, parentKilled bool) string {
	if timedOut {
		return "timeout"
	}
	if cmd.ProcessState == nil {
		return "no-status"
	}
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	switch {
	case ws.Signaled():
		name := ws.Signal().String()
		if parentKilled && ws.Signal() == syscall.SIGKILL {
			// The harness's own kill, not something the filter did.
			return "harness-kill"
		}
		return fmt.Sprintf("signal=%d(%s)", int(ws.Signal()), name)
	case ws.Exited():
		return fmt.Sprintf("exit=%d", ws.ExitStatus())
	default:
		return fmt.Sprintf("status=%v", runErr)
	}
}

// cmdRun measures every selected (case, probe) pair in this binary's build and
// prints a TSV report. Children are independent processes, so they run in
// parallel; each gets its own result page.
func cmdRun() {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}

	cs := cases()
	names := caseNames()
	var origIdx []int
	for i := range cs {
		origIdx = append(origIdx, i)
	}
	if only := os.Getenv("VMDIFF_ONLY"); only != "" {
		want := map[string]bool{}
		for _, n := range strings.Split(only, ",") {
			want[n] = true
		}
		var filtered []Case
		var filteredNames []string
		var filteredIdx []int
		for i, c := range cs {
			if want[c.Name] {
				filtered = append(filtered, c)
				filteredNames = append(filteredNames, names[i])
				filteredIdx = append(filteredIdx, i)
			}
		}
		cs, names = filtered, filteredNames
		// The child indexes the unfiltered cases() list, so the task has to
		// carry the original index, not the position in this filtered slice.
		origIdx = filteredIdx
	}

	type task struct {
		caseName        string
		caseIdx, probeI int
	}
	var tasks []task
	for i := range probes {
		tasks = append(tasks, task{"(baseline)", -1, i})
	}
	if os.Getenv("VMDIFF_BASELINE_ONLY") != "" {
		cs = nil
	}
	for ci, c := range cs {
		for pi, p := range probes {
			if probeSelected(c, p) {
				tasks = append(tasks, task{names[ci], origIdx[ci], pi})
			}
		}
	}

	results := make([]observation, len(tasks))
	workers := 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range tasks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t := tasks[i]
			progress(t.caseName, probes[t.probeI].Name)
			results[i] = runChild(self, strconv.Itoa(t.caseIdx), strconv.Itoa(t.probeI), t.caseName)
		}(i)
	}
	wg.Wait()

	for i, t := range tasks {
		emit(t.caseName, probes[t.probeI].Name, results[i])
	}
}

func probeSelected(c Case, p Probe) bool {
	if p.Core {
		return true
	}
	for _, n := range c.Probes {
		if n == p.Name {
			return true
		}
	}
	return false
}

func emit(caseName, probe string, o observation) {
	fmt.Printf("%s\t%s\t%s\t%s\t%dms\n", caseName, probe, o.result, o.exit, o.dur.Milliseconds())
}

// cmdInit is PID 1 inside the VM. It runs both builds, compares them, prints the
// divergences and powers off.
func cmdInit() {
	mountPseudo()

	self, err := os.Executable()
	if err != nil {
		self = "/runner"
	}
	cgoPath := os.Getenv("VMDIFF_CGO")
	if cgoPath == "" {
		cgoPath = "/runner-cgo"
	}

	fmt.Println("VMDIFF_BEGIN")
	fmt.Printf("go-binary: %s\n", self)
	if _, err := os.Stat(cgoPath); err != nil {
		fmt.Printf("FATAL: cgo binary %s: %v\n", cgoPath, err)
		poweroff(1)
	}

	full := os.Getenv("VMDIFF_FULL") != ""

	goLines, goRaw := runVariant(self, "go", full)
	cgoCmd := exec.Command(cgoPath, "--run")
	cgoCmd.Stderr = os.Stderr
	cgoOut, err := cgoCmd.Output()
	if err != nil {
		fmt.Printf("FATAL: cgo runner failed: %v\n", err)
		poweroff(1)
	}
	cgoLines := parseReport(string(cgoOut))
	if full {
		fmt.Printf("--- cgo raw report ---\n%s", cgoOut)
	}

	compare(goLines, cgoLines)

	_ = goRaw
	fmt.Println("VMDIFF_END")
	poweroff(0)
}

func runVariant(self, label string, full bool) (map[string]observation, string) {
	c := exec.Command(self, "--run")
	c.Stderr = os.Stderr
	out, err := c.Output()
	if err != nil {
		fmt.Printf("FATAL: %s runner failed: %v\n", label, err)
		poweroff(1)
	}
	if full {
		fmt.Printf("--- %s raw report ---\n%s", label, out)
	}
	return parseReport(string(out)), string(out)
}

func parseReport(s string) map[string]observation {
	m := map[string]observation{}
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "\t", 4)
		if len(f) < 4 {
			continue
		}
		m[f[0]+"\t"+f[1]] = observation{result: f[2], exit: f[3]}
	}
	return m
}

// primary is the observation without the diagnostic tail appended for killed
// and blocked children (the Go runtime's traceback, the compiler's log output).
// Those differ in wording between the two builds without being behavioural.
func primary(s string) string {
	if i := strings.Index(s, " ["); i >= 0 {
		return s[:i]
	}
	return s
}

func compare(goMap, cgoMap map[string]observation) {
	keys := make([]string, 0, len(goMap))
	for k := range goMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var divergences, checked int
	fmt.Println("--- divergences (go build vs libseccomp build) ---")
	for _, k := range keys {
		g, ok := goMap[k]
		c, ok2 := cgoMap[k]
		if !ok || !ok2 {
			continue
		}
		checked++
		if primary(g.result) == primary(c.result) {
			continue
		}
		divergences++
		parts := strings.SplitN(k, "\t", 2)
		fmt.Printf("DIVERGENCE case=%-38s probe=%-26s go=%-24s cgo=%s\n",
			parts[0], parts[1], g.result, c.result)
	}
	fmt.Printf("--- %d (case,probe) pairs compared, %d divergences ---\n", checked, divergences)
}

func mountPseudo() {
	for _, d := range []string{"/proc", "/sys", "/dev"} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = unix.Mount("proc", "/proc", "proc", 0, "")
	_ = unix.Mount("sysfs", "/sys", "sysfs", 0, "")
	_ = unix.Mount("devtmpfs", "/dev", "devtmpfs", 0, "")
}

func poweroff(code int) {
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(code)
}
