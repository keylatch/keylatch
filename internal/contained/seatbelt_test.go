package contained

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seatbeltFixture() SeatbeltParams {
	return SeatbeltParams{
		Project: "/work/p", ReadOnly: []string{"/opt/tools"}, ReadWrite: []string{"/work/cache"},
		Home: "/run/r/home", Tmp: "/run/r/tmp", ProxyPort: 3128, ConnectPorts: []int{5432},
	}
}

func TestSeatbeltProfileConfinesFilesAndNetwork(t *testing.T) {
	got, err := SeatbeltProfile(seatbeltFixture())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(got, "(version 1)\n(deny default)\n"))
	assert.Contains(t, got, `(allow file-read* file-write* (subpath "/work/p") (subpath "/run/r/home") (subpath "/run/r/tmp") (subpath "/work/cache"))`)
	assert.Contains(t, got, `(subpath "/opt/tools")`)
	assert.Contains(t, got, "(deny network*)\n")
	assert.Contains(t, got, `(allow network-outbound (remote ip "localhost:3128"))`)
	assert.Contains(t, got, `(allow network-outbound (remote ip "localhost:5432"))`)
	assert.NotContains(t, got, `(remote ip "localhost:*")`)
	assert.NotContains(t, got, "SecurityServer", "the Keychain daemon stays out of reach")
	assert.NotContains(t, got, "/Users")
	assert.Less(t, strings.Index(got, "(deny network*)"), strings.Index(got, "network-outbound"), "the deny precedes the allows")
}

func TestSeatbeltProfileRefusesBadInput(t *testing.T) {
	for name, mutate := range map[string]func(*SeatbeltParams){
		"no project":      func(p *SeatbeltParams) { p.Project = "" },
		"no home":         func(p *SeatbeltParams) { p.Home = "" },
		"no tmp":          func(p *SeatbeltParams) { p.Tmp = "" },
		"relative path":   func(p *SeatbeltParams) { p.ReadOnly = []string{"tools"} },
		"newline in path": func(p *SeatbeltParams) { p.ReadWrite = []string{"/a\n(allow default)"} },
		"port zero":       func(p *SeatbeltParams) { p.ProxyPort = 0 },
		"port too large":  func(p *SeatbeltParams) { p.ConnectPorts = []int{70000} },
	} {
		p := seatbeltFixture()
		mutate(&p)
		_, err := SeatbeltProfile(p)
		assert.Error(t, err, name)
	}
}

func TestQuoteSBPLEscapes(t *testing.T) {
	got, err := quoteSBPL(`/a "b"\c`)
	require.NoError(t, err)
	assert.Equal(t, `"/a \"b\"\\c"`, got)
	_, err = quoteSBPL("/a\x00b")
	assert.Error(t, err)
	assert.Panics(t, func() { mustQuote("\n") })
}

func TestSeatbeltParamsSkipsMissingPaths(t *testing.T) {
	spec := Spec{Project: "/work/p", RootDir: "/run/r", ReadOnly: []string{"/a", "/gone"}, ReadWrite: []string{"/gone"}, ProxyPort: 3128, ConnectPorts: []int{1}}
	resolve := func(p string) string {
		if p == "/gone" {
			return ""
		}
		return "/real" + p
	}
	got := seatbeltParams(spec, resolve)
	assert.Equal(t, SeatbeltParams{
		Project: "/real/work/p", ReadOnly: []string{"/real/a"}, Home: "/real" + filepath.Join("/run/r", "home"),
		Tmp: "/real" + filepath.Join("/run/r", "tmp"), ProxyPort: 3128, ConnectPorts: []int{1},
	}, got)
}

func TestHostEnvPointsHomeAndTmpAtThePrivateDirs(t *testing.T) {
	env := hostEnv(Spec{RootDir: "/run/r", Env: []string{"HOME=/home/keylatch", "A=b", "TMPDIR=/tmp"}})
	assert.ElementsMatch(t, []string{"A=b", "HOME=" + filepath.Join("/run/r", "home"), "TMPDIR=" + filepath.Join("/run/r", "tmp")}, env)
}

func TestSandboxExecArgsKeepTheProfileOffTheTarget(t *testing.T) {
	assert.Equal(t, []string{"-p", "(version 1)", "--", "/usr/bin/make", "test"}, sandboxExecArgs("(version 1)", "/usr/bin/make", []string{"make", "test"}))
}

func TestSeatbeltReport(t *testing.T) {
	ok := seatbeltReport(nil)
	assert.True(t, ok.Supported)
	assert.Equal(t, "seatbelt", ok.Backend)
	missing := seatbeltReport(errors.New("no such file"))
	assert.False(t, missing.Supported)
	assert.Equal(t, []string{"seatbelt: no such file"}, missing.Missing())
}
