//go:build linux && cgo

package libcontainer

// joinNamespaces is a no-op with cgo: the C constructor in
// libcontainer/nsenter has already joined these namespaces, before the Go
// runtime started. That timing is the whole reason the constructor exists.
func joinNamespaces(_ initType, _ []string) error { return nil }
