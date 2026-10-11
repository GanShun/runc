//go:build linux && amd64

#include "textflag.h"

// func probeAndStore(page unsafe.Pointer, abi, nr, a1, a2, a3, a4, a5, a6 uintptr)
//
// Runs exactly one syscall and then stores the result into the shared page and
// exits. It is deliberately written in assembly with no Go runtime involvement
// after the filter is installed: a filter that blocks or traps every syscall
// would otherwise make the Go runtime itself fail before the probe could run,
// and the observation would be of the runtime rather than of the filter.
//
// abi 0 is the native/x32 entry path (SYSCALL), abi 1 is the i386 compat path
// (INT 0x80). It never returns.
//
// Page offsets must match main.go: r1 0, r2 8, errno 16, flags 24, flagResult 1.
TEXT ·probeAndStore(SB),NOSPLIT|NOFRAME,$0-72
	MOVQ	page+0(FP), R12
	// Stage 4 means "the probe syscall is about to be issued". Anything below
	// it means the child died before the probe could run, which is harness
	// noise, not a filter decision.
	MOVB	$4, 27(R12)
	MOVQ	abi+8(FP), R11
	CMPQ	R11, $1
	JEQ	int80

	// Native (amd64) or x32: SYSCALL, args in DI SI DX R10 R8 R9.
	MOVQ	nr+16(FP), AX
	MOVQ	a1+24(FP), DI
	MOVQ	a2+32(FP), SI
	MOVQ	a3+40(FP), DX
	MOVQ	a4+48(FP), R10
	MOVQ	a5+56(FP), R8
	MOVQ	a6+64(FP), R9
	SYSCALL
	JMP	store

int80:
	// i386 compat: INT 0x80, args in BX CX DX SI DI BP.
	MOVQ	nr+16(FP), AX
	MOVQ	a1+24(FP), BX
	MOVQ	a2+32(FP), CX
	MOVQ	a3+40(FP), DX
	MOVQ	a4+48(FP), SI
	MOVQ	a5+56(FP), DI
	MOVQ	a6+64(FP), BP
	INT	$0x80

store:
	MOVQ	AX, 0(R12)
	MOVQ	$0, 8(R12)
	MOVQ	$0, 16(R12)
	CMPQ	AX, $0xfffff001
	JB	ok
	MOVQ	$0, 0(R12)
	NEGQ	AX
	MOVQ	AX, 16(R12)
ok:
	MOVB	$1, 24(R12)

	// Never return. exit_group, then exit, forever: either may be blocked by
	// the very filter under test, and the parent kills the process once it has
	// seen the result.
exitloop:
	MOVQ	$231, AX // SYS_EXIT_GROUP
	XORQ	DI, DI
	SYSCALL
	MOVQ	$60, AX // SYS_EXIT
	MOVQ	$1, DI
	SYSCALL
	JMP	exitloop
