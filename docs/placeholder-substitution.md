# Placeholder substitution (tier D3)

`keylatch run --tier D3 <connection> -- <command>` gives the child a worthless placeholder in the
variable its tool reads (for example `STRIPE_SECRET_KEY=sk_klph_...`) and points `HTTPS_PROXY` at a
forwarder that reaches the daemon's session proxy. The CA variables `SSL_CERT_FILE`,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE` and
`DENO_CERT` point at a temporary bundle holding the system roots and the session CA.

The tier is chosen automatically when the provider template declares host bindings.

## Guarantees

- The proxy replaces a placeholder only in a slot the template declares, toward a host the slot
  names. The real value is read from the backend at that moment and never cached.
- The session CA is generated per session, limited by Name Constraints to the session's hosts, and
  its key stays in daemon memory.
- A placeholder anywhere else (another header, the body, an undeclared query parameter, another
  host, a request whose authority differs from its tunnel, a request after a redirect to another
  authority) blocks the request, suspends the session and records a `placeholder.misuse` event.
- Responses have the real value replaced by the placeholder before the child sees them.
- Only bound hosts are reachable. IP literals, loopback, private, link-local and metadata ranges
  are refused, and the proxy resolves names itself.
- When the caller's environment names an upstream proxy (`HTTPS_PROXY`), the session sends its
  upstream connections through it.

## GitHub App tokens

`keylatch run --repo <owner/name> [--permission <name>=<level>]... github-app -- gh pr create ...` gives the child `GH_TOKEN` and `GITHUB_TOKEN` set to placeholders. The daemon mints an installation token for that one repository the first time a request needs it, keeps it in daemon memory only, mints a fresh one shortly before it expires, and revokes it when the run ends. The proxy substitutes it for `api.github.com` and `uploads.github.com` (`Bearer` and `token` schemes) and for the Basic-auth password toward `github.com`, which covers git over HTTPS.

The connection's `mint.github_app` policy in the operator's `config.json` decides who may do this. `placeholder_callers` lists the caller kinds (`agent`, `host`, `human`, `service`) allowed to run with a minted placeholder; empty means none. `allow_owners`, `allow_repos`, `deny_owners`, `permission_ceiling` and `max_ttl` apply as they do to `keylatch mint`. Without `--repo` the policy's only allowed repository is used, and without `--permission` the whole ceiling is requested. Agent and host callers still cannot print a token with `keylatch mint`.

Git asks `keylatch git-credential` for a password. The helper answers with the session's placeholder for hosts the template's git adapter names and with nothing for any other host; it never holds a real token. The session sets the helper for those hosts, clears other configured helpers and disables terminal prompts.

## Limits

- Tools must honour `HTTPS_PROXY` and a custom CA bundle; tools that pin certificates fail closed.
- WebSocket upgrades are refused with a clear error.
- Signed protocols (AWS SigV4) are not substitutable by header rewrite.
