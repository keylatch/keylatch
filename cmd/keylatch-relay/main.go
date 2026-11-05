// Command keylatch-relay forwards the request bytes on its standard input to
// the keylatchd control socket and writes the reply to standard output. It
// ignores its arguments, holds no key material and starts no process.
package main

import (
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/socketrelay"
)

func main() {
	if err := socketrelay.Run(os.Getenv, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "keylatch-relay:", err)
		os.Exit(1)
	}
}
