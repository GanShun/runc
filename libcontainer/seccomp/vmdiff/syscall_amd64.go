//go:build linux && amd64

package main

import "unsafe"

// probeAndStore runs one syscall and stores the outcome into the shared result
// page, then never returns. abi 0 is native/x32, abi 1 is i386.
//
//go:noescape
func probeAndStore(page unsafe.Pointer, abi, nr, a1, a2, a3, a4, a5, a6 uintptr)
