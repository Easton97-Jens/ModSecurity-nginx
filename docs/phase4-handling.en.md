# ModSecurity-nginx: Phase 4 Handling (English)

## 1) Scope and provenance

Phase 4 inspects the response body. nginx can already have sent headers or body
bytes when a phase 4 rule requests a deny status or redirect. A late
intervention cannot reliably replace the HTTP status already sent to the
client.

This branch adopts the relevant nginx implementation from
[Easton97-Jens/ModSecurity-conector, commit b0f3bdab429717b5b0311c30c5b4d1153c672ac0](https://github.com/Easton97-Jens/ModSecurity-conector/tree/b0f3bdab429717b5b0311c30c5b4d1153c672ac0/connectors/nginx/src).
It is adapted to this standalone module and preserves this branch's phase 4
JSON-lines schema. The source repository's multi-connector runtime and run
evidence are not imported.

This document describes source behavior. It does not claim that runtime,
protocol, or integration tests have passed for this migration.

## 2) Configuration and breaking changes

All three connector directives below are valid in `http`, `server`, and
`location` contexts and inherit from the enclosing context.

| Directive | Values | Default |
| --- | --- | --- |
| `modsecurity_phase4_mode` | `off`, `safe`, `strict` | `off` |
| `modsecurity_phase4_body_limit` | Positive byte count or nginx size, e.g. `256k`, `2m` | `1m` (1 MiB) |
| `modsecurity_phase4_log` | File path for phase 4 JSON-lines events | No dedicated log |

Migration from the previous `master-phase4` configuration requires these
changes:

- `minimal` is no longer valid and is not an alias for `off`.
- The default mode changes from `safe` to `off`. Set `safe` or `strict`
  explicitly to enable the additional connector policy.
- `modsecurity_phase4_content_types_file` is removed and causes an nginx
  configuration error. Move MIME selection into ModSecurity rules.
- The positive connector body budget is new. Choose a value suitable for your
  responses when enabling `safe` or `strict`; zero is invalid.

Validate the migrated configuration with `nginx -t` in the deployment
environment before reloading nginx.

## 3) Mode behavior and header timing

`off` disables the connector's additional phase 4 intervention policy and body
budget. It **does not disable ModSecurity**, response-body inspection, or phase
4 rules. Native intervention handling remains active. If a native intervention
occurs after headers have been committed, response finalization can fail the
transport; `off` is not a promise to deliver every response.

For the additional policy in `safe` and `strict`:

| Header state | `safe` | `strict` |
| --- | --- | --- |
| Headers not sent | Apply the intervention's status/redirect through the normal path; logged as `deny_status` | Same |
| Headers already sent | Log the intervention as `log_only` and continue | Log `connection_abort` and terminate the response |

`safe` only downgrades late **interventions**. An engine API failure, invalid
buffer, failed file read, allocation failure, counter overflow, or exceeded
body budget remains a failure. It is not converted into successful forwarding.

`strict` can produce a truncated response or a client/proxy transport error.
It cannot guarantee a clean 403, 401, 301, or 302 after headers have been sent.
Previously forwarded body bytes cannot be recalled.

## 4) Response-body budget and streaming

`modsecurity_phase4_body_limit` is a connector budget for the cumulative
response bytes it sees in `safe` and `strict`, including file-backed buffers.
It is separate from the engine's `SecResponseBodyLimit` and is not restricted
to the bytes the engine retains for inspection.

A response may reach the budget exactly. A chunk that would cross it is
rejected **before that chunk is forwarded**. Earlier chunks may already have
reached the client, so this does not guarantee a replacement HTTP error
status. In `off`, the configured connector budget is ignored, but cumulative
accounting still rejects overflow beyond `SIZE_MAX`.

The connector does not globally buffer responses or reorder nginx body
chains. Memory buffers are inspected directly. File-only buffers are read
through a bounded 32 KiB scratch buffer, without loading the entire file into
memory or replacing the original outgoing chain. Genuine processing or I/O
failures stop the affected response.

The response body is finalized once per transaction: a main request uses
`last_buf`; a subrequest uses `last_in_chain`. Repeated filter calls after
finalization do not run phase 4 again.

## 5) MIME selection belongs to ModSecurity

The engine decides response-body inspection using `SecResponseBodyAccess`,
`SecResponseBodyMimeType`, and `SecResponseBodyMimeTypesClear`. There is no
connector content-type allowlist or connector MIME-based downgrade.

For example, add these directives to your ModSecurity configuration or an
inline `modsecurity_rules` block:

```apache
SecResponseBodyAccess On
SecResponseBodyMimeTypesClear
SecResponseBodyMimeType text/html text/plain application/json
```

The standalone [engine MIME example](examples/phase4-engine-mime.conf) is a
ModSecurity rules file, not an nginx include. Load it with
`modsecurity_rules_file` alongside your other rules if you use it. The complete
nginx examples below configure MIME selection inline.

Engine selection does not disable the independent connector body budget in
`safe` or `strict`.

## 6) Logging format and security boundary

`modsecurity_phase4_log` preserves the existing JSON-lines intervention schema:

- `event` (`phase4_intervention`), `uri`, `method`;
- `response_status`, `waf_status`, `content_type`, `header_sent`, `mode`;
- `wanted_action`, `actual_action`, `reason`;
- `intervention`, `rule_id`.

The `actual_action` values remain `deny_status`, `log_only`, and
`connection_abort`; `mode` uses the current mode names. The intervention
message is redacted rather than copied from the engine, and response-body
payload is not added to this event. nginx's error log may also contain
diagnostics.

`off` uses native intervention handling and does not produce these dedicated
policy events. A dedicated intervention event is not a complete inventory of
all engine, buffer, or I/O errors.

## 7) Configuration examples and verification

- [off](examples/phase4-off.conf): native intervention handling with engine
  inspection enabled.
- [safe](examples/phase4-safe.conf): explicit late `log_only` policy and a
  1 MiB connector budget.
- [strict](examples/phase4-strict.conf): late connection termination and a
  1 MiB connector budget.
- [engine MIME selection](examples/phase4-engine-mime.conf): ModSecurity
  response-body configuration.

The nginx examples use `location /` and an example upstream at
`127.0.0.1:8081`. Adapt the listen address, upstream, log path, and rules to
your environment. The `sensitive-marker` rule is illustrative.

Repository test endpoints such as `/phase4` are test fixtures, not required
production paths. Runtime checks should cover late deny/redirect behavior,
HTTP/1.1 and HTTP/2, file-backed responses, subrequests, repeated finalization,
budget boundaries, and failure paths. Results from another repository or build
do not establish those behaviors for the deployed module.