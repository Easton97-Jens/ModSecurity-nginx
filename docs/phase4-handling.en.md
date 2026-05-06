# ModSecurity-nginx: Phase 4 Handling (English)

## Introduction: what is the `phase:4` problem?

`phase:4` rules run while processing the **response body**. In nginx, response headers may already have been sent to the client at that point. Once headers are sent, nginx cannot reliably switch HTTP status (for example to 403) or inject redirect headers anymore.

This repository adds explicit Phase 4 handling for that condition, including dedicated modes and structured logging.

## Why “headers already sent” is a problem

If a ModSecurity intervention (`deny`, `status`, `redirect`) is triggered in `phase:4`, classic blocking/redirecting only works when headers are still unsent.

If headers are already sent:

- late `status:401/403` cannot be cleanly enforced as HTTP status,
- late redirect (`301/302` + `Location`) cannot be cleanly enforced,
- only degraded reactions remain (logging, optionally aborting the connection).

## Why there is **no global response-body buffering**

The implementation intentionally avoids global buffering of large response bodies. This aligns with:

- no blanket memory/latency overhead for all responses,
- no extra reordering logic between already-sent headers and late body-time decisions,
- no false guarantee that `phase:4` can always be translated to clean HTTP block/redirect semantics.

## New directives

### `modsecurity_phase4_mode`

Supported values:

- `minimal`
- `safe`
- `strict`

Invalid values are rejected at config parsing time.

### `modsecurity_phase4_content_types_file`

Loads content types from a file (one type per line, `#` comments supported). Entries are validated; invalid entries fail configuration loading.

If not set, built-in default content types are used.

### `modsecurity_phase4_log`

Enables a dedicated JSON-lines log for Phase 4 interventions.

## Modes: behavior and safety profile

## `minimal`

- For `phase:4` interventions after headers are sent: no synthetic deny, `log_only`.
- Goal: least intrusive behavior, no forced disconnect.

## `safe`

- For late interventions, behavior is also `log_only`.
- Goal: operational stability without forced abort.

## `strict`

- For `phase:4` interventions after headers are sent: `connection_abort`.
- Goal: stricter handling when clean status/redirect changes are no longer possible.

> Important: `strict` does **not** guarantee a retroactive 401/403/301/302; it may terminate the connection instead.

## Behavior by header state

### Headers **not sent yet**

Normal ModSecurity intervention paths remain possible (for example `deny_status`), because nginx can still adjust outgoing headers.

### Headers **already sent**

- `minimal`/`safe`: `log_only`
- `strict`: `connection_abort`

## Action semantics

### `connection_abort`

- Implemented fallback in `strict` mode for late `phase:4` interventions.
- Technical effect: request terminates via error path (no post-hoc header rewrite).

### `log_only`

- Intervention is recorded, while response flow continues as far as possible.
- Provides traceability without forced transport interruption.

## Content-Type scoping (`modsecurity_phase4_content_types_file`)

Phase 4 handling is scoped by content type. If `Content-Type` is missing or not in scope, the module logs a degraded action (`log_only`, with reasons such as `content_type_missing` / `content_type_not_in_scope`) instead of enforcing a hard action.

This limits side effects on non-targeted response types.

## Logging

### `modsecurity_phase4_log`

Writes JSON lines with fields such as:

- `event` (`phase4_intervention`)
- `uri`, `method`
- `response_status`, `waf_status`
- `content_type`
- `header_sent` (boolean)
- `mode`
- `wanted_action`, `actual_action`
- `reason`
- `intervention`
- `rule_id`

### nginx `error.log`

Additionally, especially on the `strict` path, a warning is emitted to nginx error log when an intervention occurs after headers are sent.

## Security decisions (implementation)

- **No response body in Phase 4 log**: reduces leakage risk through logs.
- **No `ngx_chain_t` rewriting**: avoids brittle low-level mutations of already flowing body chains.
- **No synthetic reordering logic**: avoids inconsistent states between sent headers and late decisions.
- **`strict` may abort connections**: deliberate trade-off for stricter fail behavior without false HTTP-status guarantees.

## Example configurations

See:

- `docs/examples/phase4-minimal.conf`
- `docs/examples/phase4-safe.conf`
- `docs/examples/phase4-strict.conf`
- `docs/examples/phase4-content-types.conf`

## JSON log examples

`log_only` (for example `safe`):

```json
{"event":"phase4_intervention","uri":"/phase4","method":"GET","response_status":200,"waf_status":403,"content_type":"text/html","header_sent":true,"mode":"safe","wanted_action":"deny","actual_action":"log_only","reason":"mode_safe","intervention":"...","rule_id":"910002"}
```

`connection_abort` (`strict`):

```json
{"event":"phase4_intervention","uri":"/phase4","method":"GET","response_status":200,"waf_status":403,"content_type":"text/html","header_sent":true,"mode":"strict","wanted_action":"deny","actual_action":"connection_abort","reason":"headers_already_sent","intervention":"...","rule_id":"910003"}
```

> Field values depend on the actual request and matched rule.

## Limitations / known boundaries

- `phase:4` cannot **guarantee** that the desired block/redirect status still reaches the client as HTTP status.
- When headers are already sent, only degraded handling is possible (`log_only` or `connection_abort`).
- Content-type scoping is critical; out-of-scope responses are not hard-enforced.

## Operator guidance

1. Do not treat `phase:4` as the sole hard access-control mechanism.
2. Prefer earlier phases for hard block/redirect decisions.
3. Enable and monitor `modsecurity_phase4_log`.
4. Keep `modsecurity_phase4_content_types_file` narrowly scoped to sensitive MIME types.
5. Use `strict` only if connection aborts are operationally acceptable.
