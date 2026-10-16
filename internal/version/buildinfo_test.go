package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionFallsBackToBuildInfo(t *testing.T) {
	cases := []struct {
		name                      string
		bi                        debug.BuildInfo
		ver, commit, date         string
		wantVer, wantCommit, wDat string
	}{
		{
			name:       "module install at a commit uses the pseudo-version and its revision",
			bi:         debug.BuildInfo{Main: debug.Module{Version: "v0.9.10-0.20261016101500-0123456789ab"}},
			ver:        defaultVersion,
			commit:     unknown,
			date:       unknown,
			wantVer:    "0.9.10-0.20261016101500-0123456789ab",
			wantCommit: "0123456789ab",
			wDat:       unknown,
		},
		{
			name: "vcs stamps provide revision, time and dirty marker",
			bi: debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abcdef0123456789abcdef0123456789abcdef01"},
					{Key: "vcs.time", Value: "2026-10-16T10:15:00Z"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			ver:        defaultVersion,
			commit:     unknown,
			date:       unknown,
			wantVer:    defaultVersion,
			wantCommit: "abcdef0123456789abcdef0123456789abcdef01-dirty",
			wDat:       "2026-10-16T10:15:00Z",
		},
		{
			name:       "ldflags values win over build info",
			bi:         debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}},
			ver:        "1.2.3",
			commit:     "deadbeef",
			date:       "2026-01-01",
			wantVer:    "1.2.3",
			wantCommit: "deadbeef",
			wDat:       "2026-01-01",
		},
		{
			name:       "empty build info keeps defaults",
			bi:         debug.BuildInfo{},
			ver:        defaultVersion,
			commit:     unknown,
			date:       unknown,
			wantVer:    defaultVersion,
			wantCommit: unknown,
			wDat:       unknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, c, d := fromBuildInfo(&tc.bi, tc.ver, tc.commit, tc.date)
			assert.Equal(t, tc.wantVer, v)
			assert.Equal(t, tc.wantCommit, c)
			assert.Equal(t, tc.wDat, d)
		})
	}
}
