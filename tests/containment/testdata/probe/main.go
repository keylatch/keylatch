// Command probe is the hostile process the containment tests run inside a
// sandbox: it reports what a caller in that sandbox can reach.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(64)
	}
	switch os.Args[1] {
	case "gateway":
		gateway()
	case "hidden":
		hidden(os.Args[2])
	case "dial":
		dial(os.Args[2])
	case "fake-client":
		fakeClient(os.Args[2], os.Args[3:])
	default:
		os.Exit(64)
	}
}

// gateway sends one request to the gateway URL the child was given.
func gateway() {
	req, err := http.NewRequest(http.MethodGet, os.Getenv("KEYLATCH_GATEWAY_URL")+"/probe", nil)
	if err != nil {
		fmt.Println("request:", err)
		os.Exit(1)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("KEYLATCH_GATEWAY_TOKEN"))
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Println("gateway:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("%s|%s\n", body, os.Getenv("OPENROUTER_API_KEY"))
}

// hidden reports whether path can be listed or read.
func hidden(path string) {
	if _, err := os.Stat(path); err != nil {
		fmt.Println("hidden")
		return
	}
	fmt.Println("visible")
	os.Exit(1)
}

// dial reports whether a TCP address is reachable.
func dial(addr string) {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		fmt.Println("unreachable")
		return
	}
	_ = c.Close()
	fmt.Println("reachable")
	os.Exit(1)
}

// fakeClient speaks the control protocol directly, as a planted keylatch
// would, and prints what the daemon answers.
func fakeClient(socket string, verbArgs []string) {
	conn, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	req := map[string]any{"op": "exec", "verb": verbArgs[0], "args": verbArgs[1:]}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		os.Exit(1)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(1)
	}
	fmt.Print(string(line))
}
