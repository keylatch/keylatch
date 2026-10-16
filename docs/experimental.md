---
title: Experimental Features
since: 1.0.0
---

# Experimental features

Unfinished features are compiled only when you build Keylatch yourself with the `experimental`
build tag. Release binaries, packages and container images never include them. Everything the tag
enables is **unsupported**: it may change or disappear in any release, and parts of it do nothing
yet.

```sh
go build -tags experimental ./cmd/keylatch
```

## What the tag enables

| Area | What you get |
|------|--------------|
| `keylatch team` | Team identity, membership and role commands. |
| `keylatch trust`, `keylatch shared-secret` | Root-of-trust enrolment and shared-secret commands. The enrolment ceremonies are not implemented and exit with code 10 (not implemented). |
| `keylatch backend vault` | Vault Transit root-of-trust key wrapping (not the `vault` secret backend). |
| Root-of-trust adapters | FIDO2, GnuPG smartcard, PKCS#11, Secure Enclave, SSH agent and Vault Transit adapters, registered at start-up. |
| Team services | Approval workflows, SSO and OIDC identity, SCIM provisioning, break-glass access, CI identity, access reviews, org policy bundles and audit export. |
| Team admin UI routes | The admin route group and approval inbox stream. |

Code that Keylatch's own commands share, such as the root-of-trust types used by the key ring and
by policy, is part of every build.

## Release builds

The release pipeline builds with the tags `embedded_ui,production,release` and never
`experimental`. The `release` tag also leaves out the test-only helpers
`internal/broker/testing.go` and `internal/ui/testing.go`. A test builds both variants and checks
the symbol table of the release binary:

```sh
go test -count=1 ./internal/release/... -run '^TestReleaseBinaryHasNoExperimentalSymbols$'
```

## Testing the experimental code

```sh
go build -tags experimental ./...
go test -count=1 -tags experimental ./internal/team/... ./internal/trust/...
```

## Graduation

A feature graduates when its files lose the `//go:build experimental` line, its stub registration
is deleted and the changelog says `stabilized: <feature>`. A feature that is dropped is removed
from the tree and noted in the changelog.
