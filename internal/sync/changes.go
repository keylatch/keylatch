package sync

import (
	"slices"
	"sort"
	"time"
)

// Change kinds.
const (
	KindAdd       = "add"
	KindUpdate    = "update"
	KindUnchanged = "unchanged"
	KindExtra     = "extra"
)

// Reasons an entry is an update.
const (
	ReasonSource  = "changed source value"
	ReasonEnvs    = "changed environments"
	ReasonType    = "changed Vercel type"
	ReasonOutside = "changed outside keylatch"
	ReasonUnknown = "not written by keylatch"
)

// Change is one line of a diff. It names a variable and says what differs; it
// never holds a value.
type Change struct {
	Target      string `json:"target"`
	Environment string `json:"environment"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Reason      string `json:"reason,omitempty"`
}

// Remote is a variable as the target lists it.
type Remote struct {
	// ID is the target's own handle for the entry, when it has one.
	ID   string
	Name string
	// Environments are the environments this entry applies to: a Vercel entry's
	// targets, or the one scope (repository or an environment) of a GitHub secret.
	Environments []string
	// Type is the Vercel type ("sensitive", "encrypted", "plain"); empty elsewhere.
	Type      string
	UpdatedAt time.Time
	// Unmanaged marks entries Keylatch reports but never changes: tied to a git
	// branch, a custom environment or an integration.
	Unmanaged bool
}

// Written is what the daemon recorded after it last wrote an entry.
type Written struct {
	// MAC is the keyed hash of the value written.
	MAC string
	// RemoteAt is the update time the target reported for the write.
	RemoteAt time.Time
}

// State reads the daemon's record of its own writes.
type State interface {
	Written(targetID, env, name string) (Written, bool)
}

// ValueMAC returns the keyed hash of what the source currently holds for v at
// one target and environment. Nil means no value may be read.
type ValueMAC func(v Var, targetID, env string) (string, error)

// Compare lays the manifest over what the targets hold. valueMAC may be nil,
// which skips the comparison of values: drift uses that and reads none.
// targetIDs maps a target name to the identity state is keyed by.
func Compare(m Manifest, remote map[string][]Remote, targetIDs map[string]string, st State, valueMAC ValueMAC) ([]Change, error) {
	var out []Change
	for _, tn := range m.TargetNames() {
		t := m.Targets[tn]
		index := map[string]map[string]Remote{}
		for _, r := range remote[tn] {
			if r.Unmanaged {
				continue
			}
			if index[r.Name] == nil {
				index[r.Name] = map[string]Remote{}
			}
			for _, e := range r.Environments {
				index[r.Name][e] = r
			}
		}
		declared := map[string]bool{}
		for _, v := range m.Vars {
			envs, ok := v.To[tn]
			if !ok {
				continue
			}
			declared[v.Name] = true
			for _, e := range envs {
				c := Change{Target: tn, Environment: e, Name: v.Name}
				r, found := index[v.Name][e]
				if !found {
					c.Kind, c.Reason = KindAdd, "missing"
					out = append(out, c)
					continue
				}
				reason, err := updateReason(t, v, e, envs, r, targetIDs[tn], st, valueMAC)
				if err != nil {
					return nil, err
				}
				if reason == "" {
					c.Kind = KindUnchanged
				} else {
					c.Kind, c.Reason = KindUpdate, reason
				}
				out = append(out, c)
			}
		}
		var names []string
		for name := range index {
			if !declared[name] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			envs := make([]string, 0, len(index[name]))
			for e := range index[name] {
				envs = append(envs, e)
			}
			sort.Strings(envs)
			for _, e := range envs {
				out = append(out, Change{Target: tn, Environment: e, Name: name, Kind: KindExtra, Reason: "not in the manifest"})
			}
		}
	}
	return out, nil
}

func updateReason(t Target, v Var, env string, declaredEnvs []string, r Remote, id string, st State, valueMAC ValueMAC) (string, error) {
	if t.Type == TypeVercel {
		want := "encrypted"
		if v.IsSensitive() {
			want = "sensitive"
		}
		if r.Type != "" && r.Type != want {
			return ReasonType, nil
		}
		if !sameSet(r.Environments, declaredEnvs) {
			return ReasonEnvs, nil
		}
	}
	if st == nil {
		return "", nil
	}
	w, ok := st.Written(id, env, v.Name)
	if !ok {
		return ReasonUnknown, nil
	}
	if !r.UpdatedAt.IsZero() && r.UpdatedAt.After(w.RemoteAt) {
		return ReasonOutside, nil
	}
	if valueMAC != nil {
		mac, err := valueMAC(v, id, env)
		if err != nil {
			return "", err
		}
		if mac != w.MAC {
			return ReasonSource, nil
		}
	}
	return "", nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// Drifted reports whether any change other than unchanged exists.
func Drifted(changes []Change) bool {
	for _, c := range changes {
		if c.Kind != KindUnchanged {
			return true
		}
	}
	return false
}

// Counts summarises changes by kind.
func Counts(changes []Change) map[string]int {
	out := map[string]int{}
	for _, c := range changes {
		out[c.Kind]++
	}
	return out
}
