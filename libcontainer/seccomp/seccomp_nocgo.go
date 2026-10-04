//go:build linux && !cgo

package seccomp

// ignoreUnsupportedSeccomp is true for the cgo-free build.
//
// kubelet unconditionally requests RuntimeDefault seccomp on the pod sandbox
// (kubernetes/pkg/kubelet/kuberuntime/kuberuntime_sandbox.go), and containerd
// turns that into an OCI seccomp section. runc can only compile such a section
// with cgo plus libseccomp, so failing closed makes every pod on a cgo-free
// node unschedulable. The cgo-free build therefore warns and runs without
// seccomp rather than refusing to start the container.
//
// This is a real loss of isolation. Implementing seccomp in pure Go (assemble
// the BPF program from the runtime-spec config and install it with seccomp(2))
// would remove the need for it.
const ignoreUnsupportedSeccomp = true
