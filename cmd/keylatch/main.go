package main

import (
	"context"
	"os"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/contained"
	"github.com/keylatch/keylatch/internal/control"
)

func main() {
	// The sandbox launcher re-executes this binary as its init and exec
	// stages; they must run before anything reads arguments or the environment.
	contained.MaybeRun()
	streams := control.IO{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	if code, handled := control.Handle(context.Background(), os.Getenv, os.Args[1:], streams); handled {
		os.Exit(code)
	}

	root := cli.NewRootCommand()
	os.Exit(cli.ReportError(root, os.Args[1:], root.Execute(), os.Stderr))
}
