package contained

import (
	"errors"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
)

func TestPlanJob(t *testing.T) {
	assert.Equal(t, jobPlan{}, planJob(Limits{}, 8))
	assert.Equal(t, jobPlan{ProcessMemory: 1 << 30, ActiveProcesses: 64, CPURate: 2500}, planJob(Limits{MemoryBytes: 1 << 30, PIDs: 64, CPUPercent: 200}, 8))
	assert.Equal(t, uint32(1), planJob(Limits{CPUPercent: 1}, 64).CPURate, "a tiny share still caps")
	assert.Equal(t, uint32(10000), planJob(Limits{CPUPercent: 100000}, 1).CPURate, "the cap is the whole machine")
	assert.Equal(t, uint32(0), planJob(Limits{CPUPercent: 50}, 0).CPURate, "an unknown CPU count sets no cap")
}

func TestAppContainerNameIsStablePerRoot(t *testing.T) {
	a, b := appContainerName("/run/a"), appContainerName("/run/b")
	assert.Equal(t, a, appContainerName("/run/a"))
	assert.NotEqual(t, a, b)
	assert.Regexp(t, `^keylatch\.contained\.[0-9a-f]{16}$`, a)
}

func TestPlanGrants(t *testing.T) {
	spec := Spec{Project: "/p", ReadOnly: []string{"/ro"}, ReadWrite: []string{"/rw"}}
	assert.Equal(t, []aclGrant{{"/p", true}, {"/h", true}, {"/t", true}, {"/rw", true}, {"/ro", false}}, planGrants(spec, "/h", "/t"))
}

func TestComposeCommandLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain":      "plain",
		"":           `""`,
		"a b":        `"a b"`,
		`say "hi"`:   `"say \"hi\""`,
		`C:\dir\`:    `C:\dir\`,
		`C:\my dir\`: `"C:\my dir\\"`,
		`a\"b`:       `"a\\\"b"`,
	} {
		assert.Equal(t, want, composeCommandLine([]string{in}), in)
	}
	assert.Equal(t, `make "a b" x`, composeCommandLine([]string{"make", "a b", "x"}))
}

func TestEnvBlockIsSortedAndDoubleTerminated(t *testing.T) {
	got := utf16.Decode(envBlock([]string{"b=2", "A=1", "c=3"}))
	assert.Equal(t, "A=1\x00b=2\x00c=3\x00\x00", string(got))
	assert.Equal(t, []uint16{0, 0}, envBlock(nil))
}

func TestAppContainerReport(t *testing.T) {
	assert.True(t, appContainerReport(nil, nil).Supported)
	r := appContainerReport(errors.New("userenv missing"), nil)
	assert.False(t, r.Supported)
	assert.Equal(t, []string{"appcontainer: userenv missing"}, r.Missing())
	assert.Equal(t, []string{"job_object: no job"}, appContainerReport(nil, errors.New("no job")).Missing())
}
