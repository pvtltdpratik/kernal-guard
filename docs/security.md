# Security posture

## Current (Phase 1)

- The API binds to `127.0.0.1` by default. Non-loopback binding is refused
  unless `KG_ALLOW_REMOTE_BIND=true`.
- No authentication or authorisation exists. **Do not expose the API beyond
  localhost.** Any local process on the host can call it.
- CORS allows only the origins listed in `KG_CORS_ORIGINS`. Wildcards are rejected.
- Errors never include stack traces or exception messages.
- No endpoint executes commands, terminates processes or modifies files.

## Required before any remote deployment

1. **Authentication**: per-client API keys or OIDC bearer tokens, stored hashed
   server-side and never in frontend environment variables.
2. **Authorisation**: at minimum separate read (viewer) and triage (can PATCH
   alerts) roles. Log every alert/incident state change with the actor.
3. **TLS**: terminate HTTPS with a valid certificate, at the app or a reverse
   proxy. Never send telemetry or tokens over plaintext HTTP off-host.
4. **Rate limiting and request size limits** on all endpoints.
5. **Review of stored telemetry**: command lines and paths can contain
   sensitive data. Define retention and access policies first.

## Telemetry privacy rules

- Never collect keystrokes, passwords, clipboard contents or document contents.
- Store only the fields detection needs. Mark raw source XML as access-restricted.
