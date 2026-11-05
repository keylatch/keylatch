package presence

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func currentPID() int { return os.Getpid() }

func stdioIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// askOnTerminal shows the summary and reads one line from the terminal. Only
// the exact word "yes" approves, so a stray newline or a piped "y" does not.
func askOnTerminal(action Action, summary string) (bool, error) {
	fmt.Fprintf(os.Stderr, "\nkeylatch: approval needed for %s\n  %s\nType \"yes\" to approve, anything else cancels: ", action, summary)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return false, err
	}
	return strings.TrimSpace(line) == "yes", nil
}
