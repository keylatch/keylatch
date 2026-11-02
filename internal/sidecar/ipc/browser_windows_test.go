package ipc

import (
	"net/url"
	"testing"

	"golang.org/x/sys/windows"
)

func TestBrowserUsesNativeURLArgument(t *testing.T) {
	old := shellExecute
	t.Cleanup(func() { shellExecute = old })
	raw := "https://example.test/path?a=1&b=two%20words"
	called := false
	shellExecute = func(_ windows.Handle, verb, file, args, cwd *uint16, _ int32) error {
		called = true
		if windows.UTF16PtrToString(verb) != "open" || windows.UTF16PtrToString(file) != raw || args != nil || cwd != nil {
			t.Fatal("URL was not passed as one native target without shell arguments")
		}
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := openBrowser(parsed); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("native URL opener was not called")
	}
}
