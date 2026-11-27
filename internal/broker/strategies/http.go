package strategies

import (
	"net/http"
	"time"
)

func credentialHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	copy := *client
	// Redirects can replay credential-bearing request bodies to another host.
	copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}
