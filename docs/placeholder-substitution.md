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

## Limits

- Tools must honour `HTTPS_PROXY` and a custom CA bundle; tools that pin certificates fail closed.
- WebSocket upgrades are refused with a clear error.
- Signed protocols (AWS SigV4) are not substitutable by header rewrite.
