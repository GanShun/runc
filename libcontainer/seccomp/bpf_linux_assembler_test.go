//go:build linux

package seccomp

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// These tests drive the cBPF assembler in bpf_linux.go directly. No profile is
// known to produce a conditional jump at either side of the 255-instruction
// boundary, and none produces any of the errors the assembler reports, so the
// only way to pin that behaviour is to hand the builder a program built for it.
//
// A conditional jump's skip is 8 bits, so it reaches at most 255 instructions
// ahead; a target further than that is reached through the 32-bit unconditional
// jump instead. The boundary is the whole point of assemble's second pass, and
// getting it wrong truncates the skip silently: the target moves and the filter
// still runs.

// jumpBoundaryProg builds a program whose single conditional jump is dist
// instructions away from its target.
//
//	0:          ld  [0]              ; seccomp_data.nr
//	1:          jne 42 -> far        ; dist instructions away
//	2:          ret ERRNO            ; nr == 42
//	3..3+pad-1: dead instructions
//	far:        ret ALLOW
//
// The dead instructions are never reached: the jump is taken for every nr other
// than 42, and the other path returns. They exist only to place the target at a
// chosen distance.
func jumpBoundaryProg(dist int) *builder {
	b := &builder{}
	b.emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})
	b.jumpIf(bpf.JumpNotEqual, 42, "far")
	b.emit(bpf.RetConstant{Val: retErrno})
	for i := 0; i < dist-1; i++ {
		b.emit(bpf.ALUOpConstant{Op: bpf.ALUOpAdd, Val: 0})
	}
	b.label("far")
	b.emit(bpf.RetConstant{Val: retAllow})
	return b
}

// TestJumpWidthBoundary pins the distance at which a conditional jump has to
// grow, and that the widened form still branches the right way. A single
// instruction jump reaches exactly 255 instructions; 256 needs the pair. The
// distances below are the ones a layout with a one-instruction conditional
// produces, which is what the assembler decides on: widening adds an instruction
// of its own, so the settled distance of a widened jump is one more, and the pair
// has to land on the target from there.
func TestJumpWidthBoundary(t *testing.T) {
	tests := []struct {
		dist   int
		widens bool
	}{
		{254, false},
		{255, false}, // the last distance a single instruction reaches
		{256, true},  // the first that does not
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("distance %d", tc.dist), func(t *testing.T) {
			prog, err := jumpBoundaryProg(tc.dist).assemble()
			if err != nil {
				t.Fatalf("assemble: %v", err)
			}
			validateProgram(t, prog)

			// The program is: the load, the conditional (one or two
			// instructions), the failing return, dist-1 dead instructions and
			// the target's return.
			wantLen := tc.dist + 3
			if tc.widens {
				wantLen++
			}
			if len(prog) != wantLen {
				t.Fatalf("assembled to %d instructions, want %d: the jump %s", len(prog), wantLen,
					map[bool]string{true: "was widened", false: "was not widened"}[tc.widens])
			}
			target := len(prog) - 1 // the final return

			cond, ok := prog[1].(bpf.JumpIf)
			if !ok {
				t.Fatalf("instruction 1 is %T, want the conditional jump", prog[1])
			}
			if cond.Cond != bpf.JumpNotEqual || cond.Val != 42 {
				t.Errorf("instruction 1 is %v, want the jump the builder emitted", cond)
			}
			if !tc.widens {
				if cond.SkipTrue != uint8(tc.dist) || cond.SkipFalse != 0 {
					t.Errorf("single-instruction jump is %+v, want a skip of %d", cond, tc.dist)
				}
				if got := 1 + 1 + int(cond.SkipTrue); got != target {
					t.Errorf("the jump lands on instruction %d, want %d", got, target)
				}
			} else {
				// Fall through onto the 32-bit jump when the condition holds,
				// step over it when it does not.
				if cond.SkipTrue != 0 || cond.SkipFalse != 1 {
					t.Errorf("widened jump is %+v, want a fall-through onto the next instruction", cond)
				}
				uncond, ok := prog[2].(bpf.Jump)
				if !ok {
					t.Fatalf("instruction 2 is %T, want the 32-bit jump of the widened pair", prog[2])
				}
				// The 32-bit jump is one instruction into the pair, so it skips
				// the settled distance; that is one more than tc.dist because
				// the pair is an instruction longer than the conditional it
				// replaced.
				if uncond.Skip != uint32(tc.dist) {
					t.Errorf("32-bit jump skips %d, want %d", uncond.Skip, tc.dist)
				}
				if got := 2 + 1 + int(uncond.Skip); got != target {
					t.Errorf("the 32-bit jump lands on instruction %d, want %d", got, target)
				}
			}

			// The width is only right if the verdict is, too.
			vm, err := bpf.NewVM(prog)
			if err != nil {
				t.Fatalf("NewVM: %v", err)
			}
			for _, nr := range []uint32{0, 42, 43, 1000} {
				want := uint32(retAllow)
				if nr == 42 {
					want = uint32(retErrno)
				}
				got, err := vm.Run(seccompDataImage(nr, unix.AUDIT_ARCH_X86_64))
				if err != nil {
					t.Fatalf("Run(nr=%d): %v", nr, err)
				}
				if uint32(got) != want {
					t.Errorf("nr=%d: filter said %#x, want %#x", nr, uint32(got), want)
				}
			}
		})
	}
}

// TestAssembleErrors covers every way the assembler refuses a program. They are
// unreachable from a profile -- the tree layout never emits a jump backwards or
// to a label that is not there -- so a bug in the builder would otherwise
// produce a program that is silently wrong rather than an error.
func TestAssembleErrors(t *testing.T) {
	tests := []struct {
		name  string
		build func(b *builder)
		want  string
	}{
		{
			// The layout phase spots it, before any jump is resolved.
			name: "duplicate label",
			build: func(b *builder) {
				b.emit(bpf.RetConstant{Val: retAllow})
				b.label("twice")
				b.label("twice")
			},
			want: `duplicate label "twice"`,
		},
		{
			name: "jump to unknown label",
			build: func(b *builder) {
				b.jumpIf(bpf.JumpEqual, 1, "nowhere")
				b.emit(bpf.RetConstant{Val: retAllow})
			},
			want: `jump to unknown label "nowhere"`,
		},
		{
			// Refused by the settle pass, which is the first place a distance is
			// computed; it never reaches the emit step.
			name: "conditional jump goes backwards",
			build: func(b *builder) {
				b.label("back")
				b.emit(bpf.RetConstant{Val: retAllow})
				b.jumpIf(bpf.JumpEqual, 1, "back")
			},
			want: `jump to "back" goes backwards`,
		},
		{
			name: "unconditional jump goes backwards",
			build: func(b *builder) {
				b.label("back")
				b.emit(bpf.RetConstant{Val: retAllow})
				b.jumpTo("back")
			},
			want: `jump to "back" goes backwards`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := &builder{}
			tc.build(b)
			prog, err := b.assemble()
			if err == nil {
				t.Fatalf("assemble accepted it (%d instructions), want an error containing %q", len(prog), tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("assemble: %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// TestAssembleSettles pins the pass budget in assemble rather than its
// "jump layout did not settle" error, which cannot be reached: a conditional
// jump's size only ever goes from one instruction to two, because a distance
// only grows as other jumps grow, so no instruction can be widened twice. Each
// pass that changes something therefore widens at least one instruction that
// stays widened, and there are as many passes as there are ops.
//
// The program here is the shape that needs the most passes available: hundreds
// of conditional jumps to one label at the very end, so widening the early ones
// pushes the later ones over the boundary in turn.
func TestAssembleSettles(t *testing.T) {
	const jumps = 600
	b := &builder{}
	b.emit(bpf.LoadAbsolute{Off: seccompDataNr, Size: 4})
	for i := 0; i < jumps; i++ {
		b.jumpIf(bpf.JumpNotEqual, uint32(i), "end")
	}
	b.label("end")
	b.emit(bpf.RetConstant{Val: retAllow})

	prog, err := b.assemble()
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	validateProgram(t, prog)

	// Every jump past the first 255 instructions has to be a pair, and the
	// ones before it must not be.
	widened := 0
	for _, ins := range prog {
		if j, ok := ins.(bpf.JumpIf); ok && j.SkipTrue == 0 && j.SkipFalse == 1 {
			widened++
		}
	}
	if widened == 0 {
		t.Error("no jump was widened, so the program does not exercise the settling pass at all")
	}
	t.Logf("%d jumps: %d instructions, %d widened", jumps, len(prog), widened)
}
