package main

import (
	"os"

	"github.com/opencontainers/runc/libcontainer"
	_ "github.com/opencontainers/runc/libcontainer/nsenter"
)

func init() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			// This is the golang entry point for runc init, executed
			// before main() but after libcontainer/nsenter's nsexec().
			libcontainer.Init()
		case libcontainer.RuncNsCommand:
			// The exec staging stage, re-executed from this same binary with
			// the container's PID namespace to be placed in and the program
			// to run there. It is dispatched here for the same reasons as
			// "init": it is not part of the user-facing interface, it takes
			// no flags, and it must run before anything in main() has had a
			// chance to touch this process.
			libcontainer.RunRuncNs(os.Args[2:])
		}
	}
}
