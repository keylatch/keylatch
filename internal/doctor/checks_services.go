package doctor

import (
	"context"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ServiceState is what doctor learns about the enrolled service units.
type ServiceState struct {
	// Unreachable says why the enrollments could not be listed; empty when they could.
	Unreachable string
	Services    []brokerapi.ServiceInfo
}

// probeServices asks the daemon for the enrolled units and whether each still
// matches what was enrolled.
func probeServices(ctx context.Context, env llmcontext.Lookup) ServiceState {
	resp, err := brokerCall(ctx, env, brokerapi.Request{Op: brokerapi.OpServiceList, Service: &brokerapi.ServiceRequest{}})
	switch {
	case err != nil:
		return ServiceState{Unreachable: err.Error()}
	case !resp.OK || resp.Service == nil:
		return ServiceState{Unreachable: resp.Error}
	}
	return ServiceState{Services: resp.Service.Services}
}

// serviceChecks are the doctor rows for service credentials. probe is replaced in tests.
func serviceChecks(env llmcontext.Lookup, probe func(context.Context, llmcontext.Lookup) ServiceState) []namedCheck {
	return []namedCheck{plain("daemon", func(ctx context.Context) Status {
		st := serviceUnitsRow(probe(ctx, env))
		st.Name, st.Section = "services.units", "daemon"
		st.Tags = append(st.Tags, "service")
		return st
	})}
}

// serviceUnitsRow fails for an enrolled unit whose file, drop-ins or ExecStart
// changed since enrollment: the daemon would deny it, so the service has lost
// its secret until it is enrolled again.
func serviceUnitsRow(s ServiceState) Status {
	switch {
	case s.Unreachable != "":
		return Status{OK: true, Skipped: true, Detail: "enrolled service units were not checked: " + s.Unreachable}
	case len(s.Services) == 0:
		return Status{OK: true, Skipped: true, Detail: "no service units are enrolled"}
	}
	var changed, fixes []string
	for _, svc := range s.Services {
		if !svc.Changed {
			continue
		}
		changed = append(changed, fmt.Sprintf("%s (%s): %s", svc.Unit, svc.Connection, svc.Detail))
		scope := ""
		if svc.Scope == "user" {
			scope = " --scope user"
		}
		fixes = append(fixes, fmt.Sprintf("keylatch service enroll %s --unit %s%s", svc.Connection, svc.Unit, scope))
	}
	if len(changed) == 0 {
		return Status{OK: true, Detail: fmt.Sprintf("%d enrolled service unit(s) match their enrollment", len(s.Services))}
	}
	return Status{
		Detail: "enrolled units changed since enrollment, so the daemon denies them: " + strings.Join(changed, "; "),
		Fix:    "Review the change, then re-enroll: " + strings.Join(fixes, "; "),
	}
}
