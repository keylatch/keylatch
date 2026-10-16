package brokerapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/keylatch/keylatch/internal/sync"
)

// SyncRequest carries a sync manifest to the daemon. The daemon reads the
// values and talks to the targets; the client sends what only it can see: the
// manifest text, the project ids of `link` targets and the variable names of
// env files.
type SyncRequest struct {
	Manifest []byte `json:"manifest"`
	// Root is the repository's absolute path; it only names env files in the
	// daemon's record of its writes.
	Root string `json:"root,omitempty"`
	// Links maps a target name to the Vercel project id its link file names.
	Links map[string]string `json:"links,omitempty"`
	// LinkTeams maps a target name to the team id its link file names.
	LinkTeams map[string]string `json:"link_teams,omitempty"`
	// EnvKeys maps an env-file target to the names its file defines.
	EnvKeys map[string][]string `json:"env_keys,omitempty"`
	// EnvFiles names the env-file targets whose file descriptors follow the
	// request: the existing file read-only, then the new temp file.
	EnvFiles       []string `json:"env_files,omitempty"`
	Prune          bool     `json:"prune,omitempty"`
	Name           string   `json:"name,omitempty"`
	Target         string   `json:"target,omitempty"`
	KeepOldSeconds int64    `json:"keep_old_seconds,omitempty"`
	NoRollback     bool     `json:"no_rollback,omitempty"`
}

// SyncResult is what a sync operation reports: names, targets, environments,
// kinds and outcomes. Never a value.
type SyncResult struct {
	Changes []sync.Change `json:"changes,omitempty"`
	Entries []sync.Entry  `json:"entries,omitempty"`
	Drift   bool          `json:"drift,omitempty"`
	// Credentials names, per target, the kind of credential the daemon calls
	// the target API with: "token" or "github-app". Names only.
	Credentials map[string]string `json:"credentials,omitempty"`
}

// CodeSendFiles is the interim answer to a request whose file descriptors the
// client must now send.
const CodeSendFiles = "send_files"

// ServiceRequest enrolls, revokes, lists or releases a service credential.
type ServiceRequest struct {
	Connection     string   `json:"connection,omitempty"`
	Units          []string `json:"units,omitempty"`
	Unit           string   `json:"unit,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	AllowTransient bool     `json:"allow_transient,omitempty"`
	// Capability is the bytes read from the unit's credential file.
	Capability []byte `json:"capability,omitempty"`
}

// ServiceInfo describes one enrolled unit.
type ServiceInfo struct {
	Connection     string `json:"connection"`
	Unit           string `json:"unit"`
	Scope          string `json:"scope"`
	AllowTransient bool   `json:"allow_transient"`
	ExecStart      string `json:"exec_start,omitempty"`
	UnitSHA256     string `json:"unit_sha256"`
	Enrolled       string `json:"enrolled"`
	// Changed reports that the unit's file, drop-ins or ExecStart differ from
	// what was enrolled, or that the unit cannot be inspected; Detail says why.
	Changed bool   `json:"changed,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// ServiceResult answers a service operation.
type ServiceResult struct {
	Services []ServiceInfo `json:"services,omitempty"`
	// Capability is the unit-bound capability, returned once at enrollment so
	// the client can seal it into the unit's credential file.
	Capability []byte `json:"capability,omitempty"`
	// Env is what a verified service unit is released: the environment
	// variables its connection's runtime contract names.
	Env []ServiceEnv `json:"env,omitempty"`
}

// ServiceEnv is one environment variable released to a service unit.
type ServiceEnv struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// MachineRequest issues, revokes or lists machine credentials.
type MachineRequest struct {
	Name       string   `json:"name,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	Caps       []string `json:"caps,omitempty"`
	TTLSeconds int64    `json:"ttl_seconds,omitempty"`
	// PublicKey is the client's Ed25519 public key; the private key never
	// leaves the client.
	PublicKey []byte `json:"public_key,omitempty"`
	// Listen is the address the machine listener binds (machine.listen);
	// AllowWildcard permits an unspecified host.
	Listen        string `json:"listen,omitempty"`
	AllowWildcard bool   `json:"allow_wildcard,omitempty"`
}

// MachineInfo describes one issued credential.
type MachineInfo struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain"`
	Caps     []string `json:"caps"`
	Serial   string   `json:"serial"`
	NotAfter string   `json:"not_after"`
	Revoked  bool     `json:"revoked"`
}

// MachineResult answers a machine operation.
type MachineResult struct {
	Certificate []byte        `json:"certificate,omitempty"`
	CA          []byte        `json:"ca,omitempty"`
	Machines    []MachineInfo `json:"machines,omitempty"`
}

const (
	maxManifest = 256 << 10
	maxKeepOld  = 24 * 3600
	maxMachineT = 365 * 24 * 3600
)

var (
	unitName    = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]{1,250}\.service$`)
	machineName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	domainName  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	capName     = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,63}$`)
	connName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	targetName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

func (r Request) validateExtra() error {
	switch r.Op {
	case OpSyncDiff, OpSyncDrift, OpSyncApply, OpSyncRotate:
		return r.validateSync()
	case OpServiceEnroll, OpServiceRevoke, OpServiceList, OpServiceRelease:
		return r.validateService()
	}
	return r.validateMachine()
}

func (r Request) validateSync() error {
	s := r.Sync
	if s == nil || len(s.Manifest) == 0 || len(s.Manifest) > maxManifest {
		return errors.New("a sync request needs a manifest of up to 256 KiB")
	}
	if len(s.Links) > 64 || len(s.LinkTeams) > 64 || len(s.EnvKeys) > 64 || len(s.EnvFiles) > 16 {
		return errors.New("too many sync targets")
	}
	for t, id := range s.Links {
		if !targetName.MatchString(t) || id == "" || len(id) > 128 {
			return errors.New("malformed link")
		}
	}
	for t, names := range s.EnvKeys {
		if !targetName.MatchString(t) || len(names) > 4096 {
			return errors.New("malformed env file keys")
		}
	}
	for _, t := range s.EnvFiles {
		if !targetName.MatchString(t) {
			return errors.New("malformed env file target")
		}
	}
	if s.KeepOldSeconds < 0 || s.KeepOldSeconds > maxKeepOld {
		return errors.New("keep-old must be between 0 and 24 hours")
	}
	if r.Op == OpSyncRotate && (s.Name == "" || len(s.Name) > 128) {
		return errors.New("sync.rotate needs a variable name")
	}
	if len(s.Target) > 64 || len(s.Root) > 4096 || strings.ContainsRune(s.Root, 0) {
		return errors.New("malformed target or root")
	}
	if r.Op != OpSyncApply && len(s.EnvFiles) > 0 {
		return errors.New("only sync.apply and sync.rotate take file descriptors")
	}
	return nil
}

func (r Request) validateService() error {
	s := r.Service
	if s == nil {
		return errors.New("a service request is required")
	}
	if r.Op == OpServiceList {
		return nil
	}
	if !connName.MatchString(s.Connection) {
		return errors.New("a connection name is required")
	}
	switch r.Op {
	case OpServiceEnroll:
		if len(s.Units) == 0 || len(s.Units) > 16 {
			return errors.New("enroll 1 to 16 units")
		}
		for _, u := range s.Units {
			if !unitName.MatchString(u) {
				return fmt.Errorf("%q is not a service unit name", u)
			}
		}
		if s.Scope != "system" && s.Scope != "user" {
			return errors.New("the scope must be system or user")
		}
	case OpServiceRevoke:
		if s.Unit != "" && !unitName.MatchString(s.Unit) {
			return fmt.Errorf("%q is not a service unit name", s.Unit)
		}
	case OpServiceRelease:
		if len(s.Capability) != 32 {
			return errors.New("a service release needs the 32-byte capability")
		}
	}
	return nil
}

func (r Request) validateMachine() error {
	m := r.Machine
	if m == nil {
		return errors.New("a machine request is required")
	}
	if r.Op == OpMachineList {
		return nil
	}
	if r.Op == OpMachineListen {
		if m.Listen == "" || len(m.Listen) > 300 || strings.ContainsRune(m.Listen, 0) {
			return errors.New("an address to listen on is required")
		}
		return nil
	}
	if !machineName.MatchString(m.Name) {
		return errors.New("a machine name of lower-case letters, digits and dashes is required")
	}
	if r.Op == OpMachineRevoke {
		return nil
	}
	if !domainName.MatchString(m.Domain) {
		return errors.New("a domain (namespace) is required")
	}
	if len(m.Caps) == 0 || len(m.Caps) > 32 {
		return errors.New("1 to 32 capabilities are required")
	}
	for _, c := range m.Caps {
		if !capName.MatchString(c) {
			return fmt.Errorf("%q is not a capability name", c)
		}
	}
	if m.TTLSeconds < 60 || m.TTLSeconds > maxMachineT {
		return errors.New("the lifetime must be between a minute and a year")
	}
	if len(m.PublicKey) != 32 {
		return errors.New("an Ed25519 public key (32 bytes) is required")
	}
	return nil
}

// digestExtra adds the sync, service and machine fields to the request digest.
// Requests without them digest exactly as before.
func (r Request) digestExtra(field func([]byte)) {
	if r.Sync != nil {
		s := *r.Sync
		sum := sha256.Sum256(s.Manifest)
		s.Manifest = sum[:]
		b, _ := json.Marshal(s)
		field([]byte("sync"))
		field(b)
	}
	if r.Service != nil {
		s := *r.Service
		sum := sha256.Sum256(s.Capability)
		s.Capability = sum[:]
		b, _ := json.Marshal(s)
		field([]byte("service"))
		field(b)
	}
	if r.Machine != nil {
		b, _ := json.Marshal(*r.Machine)
		field([]byte("machine"))
		field(b)
	}
}

func (r Request) describeExtra(short string) (action, summary string, ok bool) {
	switch r.Op {
	case OpSyncApply:
		extra := ""
		if r.Sync != nil && r.Sync.Prune {
			extra = "; also DELETE the names the manifest does not list (--prune)"
		}
		return "sync.apply", fmt.Sprintf("Write deploy secrets: %s%s (request %s)", syncSummary(r.Sync, ""), extra, short), true
	case OpSyncRotate:
		return "sync.rotate", fmt.Sprintf("Rotate %s: %s (request %s)", r.Sync.Name, syncSummary(r.Sync, r.Sync.Name), short), true
	case OpServiceEnroll:
		return "service.enroll", fmt.Sprintf("Let %s (%s scope) receive the credential %q (request %s)", strings.Join(r.Service.Units, ", "), r.Service.Scope, r.Service.Connection, short), true
	case OpServiceRevoke:
		who := "every unit"
		if r.Service.Unit != "" {
			who = r.Service.Unit
		}
		return "service.revoke", fmt.Sprintf("Stop %s receiving the credential %q (request %s)", who, r.Service.Connection, short), true
	case OpMachineIssue:
		return "machine.issue", fmt.Sprintf("Issue machine credential %q for domain %q with %s, valid %ds (request %s)", r.Machine.Name, r.Machine.Domain, strings.Join(r.Machine.Caps, ","), r.Machine.TTLSeconds, short), true
	case OpMachineRevoke:
		return "machine.revoke", fmt.Sprintf("Revoke machine credential %q (request %s)", r.Machine.Name, short), true
	case OpMachineListen:
		wild := ""
		if r.Machine.AllowWildcard {
			wild = " on ALL interfaces if it names an unspecified host"
		}
		return "machine.listen", fmt.Sprintf("Let remote machines with a credential reach this broker at %s%s (request %s)", r.Machine.Listen, wild, short), true
	}
	return "", "", false
}

func syncSummary(s *SyncRequest, only string) string {
	if s == nil {
		return "an unreadable manifest"
	}
	return sync.Summarize(s.Manifest, only, s.Target)
}
