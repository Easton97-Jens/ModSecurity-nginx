# Phase:4 Intervention Analysis (ModSecurity-nginx Connector)

This note documents verified code paths and a minimal implementation strategy for phase:4 interventions **without** response-body global buffering, **without** ngx_chain_t reordering, and with minimal operational overhead.

## Verified current behavior

- `ngx_http_modsecurity_header_filter` sets `r->filter_need_in_memory = 1`, sends response headers into ModSecurity (`msc_add_n_response_header` + `msc_process_response_headers`), then checks intervention via `ngx_http_modsecurity_process_intervention(...)`. On positive return, it finalizes the request with the returned status code. Otherwise it forwards to `ngx_http_next_header_filter(r)`. 
- `ngx_http_modsecurity_body_filter` iterates incoming `ngx_chain_t *in` **in-place** (`for (; chain != NULL; chain = chain->next)`), appends each chunk to ModSecurity (`msc_append_response_body`), checks intervention after each chunk, and calls `msc_process_response_body` once `last_buf` is reached, then checks intervention again.
- `ngx_http_modsecurity_process_intervention` checks `r->header_sent` before applying redirect/status interventions. If headers were already sent it returns `-1`; otherwise it returns the configured disruptive status.
- In body filter, `ret > 0` leads to finalize/status handling. `ret < 0` is converted to `ngx_http_filter_finalize_request(..., NGX_HTTP_INTERNAL_SERVER_ERROR)` only in the post-`msc_process_response_body` branch.
- There is no `ngx_http_modsecurity_finalize_request` function in this repository.

## Verified constraints / observability

- `r->header_sent` is **read** in `ngx_http_modsecurity_process_intervention` (two places) but not written in connector code.
- Where `r->header_sent` is set in nginx core is **not present in this repository** and therefore **nicht belegbar** from connector code alone.
- `ngx_http_next_header_filter` is captured in `ngx_http_modsecurity_header_filter_init` and called in early-return paths and on the normal pass-through path.
- Body filter currently forwards original `in` chain unchanged to `ngx_http_next_body_filter(r, in)` when no terminal action is taken.

## Minimal patch strategy (conceptual, no chain rewrite)

1. Keep all existing body-chain handling as-is (no copy/reorder/rebuild of `ngx_chain_t`).
2. In `ngx_http_modsecurity_body_filter`, when intervention check yields `ret < 0` (headers already sent case from `ngx_http_modsecurity_process_intervention`):
   - set `r->connection->error = 1`;
   - return `NGX_ERROR`.
3. Keep existing `ret > 0` handling unchanged:
   - if headers not sent, `ngx_http_filter_finalize_request(..., ret)` remains valid deny path.
4. Keep `ngx_http_modsecurity_process_intervention` logging behavior (`modsecurity_use_error_log`) and rely on ModSecurity audit logging for full security record.
5. Add a single concise nginx error log line in the new `ret < 0` body-filter branch (optional but minimal), to avoid duplicate noisy logs.

## Why this matches requested goals

- No global response buffering added.
- No `ngx_chain_t` mutation/reordering introduced.
- No extra latency-inducing pass introduced.
- Header-not-sent path remains status deny; header-sent path becomes hard connection abort.

## Scope limits (explicit)

- Exact nginx-core runtime semantics between `r->connection->error = 1` and downstream socket teardown are **nicht belegbar** from this repository alone.
- Comparative claims about specific PRs `#334/#344` are **nicht belegbar** unless those diffs are provided or fetched externally.
