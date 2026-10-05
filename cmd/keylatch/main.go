package main

import (
	"os"

	"github.com/keylatch/keylatch/internal/cli"
)

func main() {
	root := cli.NewRootCommand()
	os.Exit(cli.ReportError(root, os.Args[1:], root.Execute(), os.Stderr))
}
