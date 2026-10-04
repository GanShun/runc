//go:build !linux || (cgo && !seccomp)

package seccomp

// ignoreUnsupportedSeccomp is false everywhere except the cgo-free build, so
// the fail-closed behaviour is unchanged for cgo builds.
const ignoreUnsupportedSeccomp = false
