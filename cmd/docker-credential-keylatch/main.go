// Command docker-credential-keylatch is the Docker credential helper behind
// `"credsStore": "keylatch"`. It asks the keylatchd control socket for the
// session's credential and prints a placeholder, never a real credential. It
// holds no key material and starts no process.
package main

import (
	"os"

	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

func main() {
	os.Exit(control.RunDockerCredential(llmcontext.DefaultLookup, os.Args[1:], control.IO{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}))
}
