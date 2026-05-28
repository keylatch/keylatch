package doctor

import (
	"context"
	"fmt"
	"runtime"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// checkVersionBinary reports the current binary version and cipher suite.
func checkVersionBinary() Check {
	return func(_ context.Context) Status {
		v := version()
		cs := CipherSuite()
		return Status{
			Name:    "version.binary",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("version=%s cipher_suite=%s fips=%v", v, cs, FIPSBuild()),
			Tags:    []string{"version"},
		}
	}
}

// checkPlatform reports runtime.GOOS/GOARCH.
func checkPlatform() Check {
	return func(_ context.Context) Status {
		plat := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
		supported := runtime.GOOS == "darwin" || runtime.GOOS == "linux" || runtime.GOOS == "windows"
		detail := fmt.Sprintf("platform=%s", plat)
		fix := ""
		if !supported {
			fix = fmt.Sprintf("Platform %q is not officially supported; proceed with caution.", runtime.GOOS)
		}
		return Status{
			Name:    "platform",
			Section: "environment",
			OK:      supported,
			Detail:  detail,
			Fix:     fix,
			Tags:    []string{"platform"},
		}
	}
}

// checkLLMSession reports the LLM session detection result.
func checkLLMSession(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		isLLM := llmcontext.IsLLMSession(env)
		reasons := llmcontext.Reasons(env)
		detail := "llm_session=false"
		if isLLM {
			detail = fmt.Sprintf("llm_session=true reasons=%v", reasons)
		}
		return Status{
			Name:    "llm.session",
			Section: "environment",
			OK:      true,
			Warn:    isLLM,
			Detail:  detail,
			Tags:    []string{"llm"},
		}
	}
}

// checkPathsConfig checks that the config directory exists and has safe modes.
func checkPathsConfig(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		p := paths.ConfigDir(env)
		if err := paths.AssertSafeModes(p); err != nil {
			s := pathStatus("paths.config", p, err)
			s.Section = "environment"
			return s
		}
		return Status{
			Name:    "paths.config",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("path=%s mode=0700", p),
			Tags:    []string{"paths"},
		}
	}
}

// checkPathsVault checks that the vault directory exists and has safe modes.
func checkPathsVault(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		p := paths.Vault(env)
		if err := paths.AssertSafeModes(p); err != nil {
			s := pathStatus("paths.vault", p, err)
			s.Section = "environment"
			return s
		}
		return Status{
			Name:    "paths.vault",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("path=%s mode=0700", p),
			Tags:    []string{"paths"},
		}
	}
}

// checkPathsAudit checks that the audit log exists and has safe modes.
func checkPathsAudit(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		p := paths.Audit(env)
		if err := paths.AssertSafeModes(p); err != nil {
			s := pathStatus("paths.audit", p, err)
			s.Section = "environment"
			return s
		}
		return Status{
			Name:    "paths.audit",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("path=%s mode=0600", p),
			Tags:    []string{"paths"},
		}
	}
}

// pathStatus builds a Status for a path check error.
func pathStatus(name, p string, err error) Status {
	var pnf *paths.PathNotFound
	if isPathNotFound(err, &pnf) {
		return Status{
			Name:   name,
			OK:     false,
			Detail: fmt.Sprintf("path=%s not found", p),
			Fix:    "Run `keylatch bootstrap` to initialize the keylatch directory.",
			Tags:   []string{"paths"},
		}
	}
	return Status{
		Name:   name,
		OK:     false,
		Detail: fmt.Sprintf("path=%s unsafe: %v", p, err),
		Fix:    fmt.Sprintf("Run `chmod 0700 %s` or `chmod 0600 %s` as appropriate.", p, p),
		Tags:   []string{"paths"},
	}
}

// isPathNotFound checks if err is a *paths.PathNotFound.
func isPathNotFound(err error, out **paths.PathNotFound) bool {
	if err == nil {
		return false
	}
	if pnf, ok := err.(*paths.PathNotFound); ok {
		if out != nil {
			*out = pnf
		}
		return true
	}
	return false
}
