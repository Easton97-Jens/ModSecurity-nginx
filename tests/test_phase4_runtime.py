"""Compile and exercise the production Phase4 helpers with small host doubles.

These tests cover accounting, buffer representations, EOS, and intervention
dispatch. Native NGINX/libModSecurity HTTP tests remain in modsecurity*.t.
There is no dependency on the Common connector or its runtime framework.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BODY = ROOT / "src" / "ngx_http_modsecurity_body_filter.c"


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} pair")


def function_definition(source: str, name: str) -> str:
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
        opening = source.index("(", match.start())
        closing = matching_delimiter(source, opening, "(", ")")
        cursor = closing + 1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "{":
            continue
        end = matching_delimiter(source, cursor, "{", "}")
        start = source.rfind("\n", 0, match.start()) + 1
        return source[start:end + 1]
    raise AssertionError(f"{name} definition was not found")


PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef _MSC_VER
typedef intptr_t ssize_t;
#endif
typedef unsigned char u_char;
typedef int ngx_int_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int error; void *log; } ngx_connection_t;
typedef struct { u_char *data; size_t length; } ngx_file_t;
typedef struct {
    u_char *pos, *last;
    off_t file_pos, file_last;
    ngx_file_t *file;
    unsigned memory, in_file, last_buf, last_in_chain;
} ngx_buf_t;
typedef struct ngx_chain_s {
    ngx_buf_t *buf;
    struct ngx_chain_s *next;
} ngx_chain_t;
typedef struct {
    size_t response_body_bytes_seen, response_body_bytes_inspected;
    int response_body_seen, response_body_truncated, phase4_processed;
    int phase4_strict_abort, phase4_headers_checked, intervention_triggered;
    int intervention_late, intervention_failed, response_replaced, last_intervention_status;
    void *modsec_transaction;
    u_char *phase4_file_scratch;
} ngx_http_modsecurity_ctx_t;
typedef struct {
    unsigned phase4_mode;
    size_t phase4_body_limit;
} ngx_http_modsecurity_conf_t;
typedef struct ngx_http_request_s {
    int header_sent;
    struct ngx_http_request_s *main;
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
} ngx_http_request_t;
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_AGAIN (-2)
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_FORBIDDEN 403
#define NGX_HTTP_MODSEC_PHASE4_MODE_OFF 0
#define NGX_HTTP_MODSEC_PHASE4_MODE_SAFE 1
#define NGX_HTTP_MODSEC_PHASE4_MODE_STRICT 2
#define NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK 32768U
#define ngx_buf_in_memory(buffer) ((buffer)->memory)
#define ngx_http_modsecurity_get_module_ctx(r) ((r)->ctx)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define ngx_log_error(...) ((void)0)
static int ngx_http_modsecurity_module;
static int allocation_calls, read_calls, append_calls, process_calls;
static int fail_allocation, fail_read, short_read, fail_append, append_result = 1;
static int engine_result = 1, native_result, native_late, native_failed;
static int log_result, event_calls, pcre_enter, pcre_leave;
static int forward_calls, forwarded_links, forward_result;
static size_t read_max, appended_bytes;
static u_char scratch[32768], inspected[200000];
static const char *last_action, *last_reason;

static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes)
{
    (void)pool;
    ++allocation_calls;
    return !fail_allocation && bytes <= sizeof(scratch) ? scratch : NULL;
}
static ssize_t ngx_read_file(ngx_file_t *file, u_char *out,
    size_t bytes, off_t offset)
{
    ++read_calls;
    if (bytes > read_max) read_max = bytes;
    if (fail_read || offset < 0) return -1;
    if ((size_t)offset > file->length || bytes > file->length - (size_t)offset)
        return 0;
    if (short_read && bytes != 0U) --bytes;
    memcpy(out, file->data + offset, bytes);
    return (ssize_t)bytes;
}
static int msc_append_response_body(void *transaction, u_char *data, size_t bytes)
{
    (void)transaction;
    ++append_calls;
    if (fail_append || bytes > sizeof(inspected) - appended_bytes) return -1;
    memcpy(inspected + appended_bytes, data, bytes);
    appended_bytes += bytes;
    return append_result;
}
static int msc_process_response_body(void *transaction)
{
    (void)transaction;
    ++process_calls;
    return engine_result;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ++pcre_enter;
    return pool;
}
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool)
{
    (void)pool;
    ++pcre_leave;
}
static int ngx_http_modsecurity_process_intervention(void *transaction,
    ngx_http_request_t *r, int early)
{
    (void)transaction; (void)early;
    r->ctx->intervention_late = native_late;
    r->ctx->intervention_failed = native_failed;
    return native_result;
}
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
    int *module, int status)
{
    (void)module;
    return r->header_sent ? NGX_ERROR : status;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r,
    ngx_http_modsecurity_conf_t *conf, const char *wanted,
    const char *actual, const char *reason)
{
    (void)r; (void)conf; (void)wanted;
    ++event_calls;
    last_action = actual; last_reason = reason;
    return log_result;
}
static ngx_int_t ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    (void)r;
    ++forward_calls;
    for (; in != NULL; in = in->next) ++forwarded_links;
    return forward_result;
}
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
"""

CASES = r"""
int main(int argc, char **argv)
{
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_modsecurity_conf_t conf = {NGX_HTTP_MODSEC_PHASE4_MODE_SAFE, 1048576U};
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_request_t request = {0};
    ngx_http_request_t main_request = {0};
    u_char payload[70000];
    ngx_file_t file = {payload, sizeof(payload)};
    ngx_buf_t buffer = {0};
    ngx_buf_t final = {0};
    ngx_chain_t tail = {&final, NULL};
    ngx_chain_t chain = {&buffer, &tail};
    size_t allowed = 999U;
    size_t i;
    CHECK(argc == 2);
    memset(payload, 'A', sizeof(payload));
    request.pool = &pool; request.connection = &connection;
    request.ctx = &ctx; request.conf = &conf; request.main = &request;
    buffer.file = &file; buffer.in_file = 1; buffer.file_last = sizeof(payload);

    if (strcmp(argv[1], "off-large") == 0) {
        conf.phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_OFF;
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1048577U, &allowed) == NGX_OK);
        CHECK(allowed == 1048577U && ctx.response_body_bytes_seen == allowed);
        CHECK(ctx.response_body_seen && !ctx.response_body_truncated);
        CHECK(ctx.response_body_bytes_inspected == 0U);
    } else if (strcmp(argv[1], "off-multiple") == 0) {
        conf.phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_OFF;
        for (i = 0; i < 3; ++i) {
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1048576U, &allowed) == NGX_OK);
            CHECK(allowed == 1048576U);
            ctx.response_body_bytes_inspected += allowed;
        }
        CHECK(ctx.response_body_bytes_seen == 3U * 1048576U);
        CHECK(!ctx.response_body_truncated);
    } else if (strcmp(argv[1], "budget-boundary") == 0) {
        for (i = 1; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); conf.phase4_mode = (unsigned)i;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1048575U, &allowed) == NGX_OK);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1U, &allowed) == NGX_OK);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1U, &allowed) == NGX_ERROR);
            CHECK(allowed == 0U && ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_seen == 1048577U);
            CHECK(ctx.response_body_bytes_inspected == 1048576U);
        }
    } else if (strcmp(argv[1], "oversized-first") == 0) {
        for (i = 1; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); conf.phase4_mode = (unsigned)i;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1048577U, &allowed) == NGX_ERROR);
            CHECK(allowed == 0U && ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_inspected == 0U);
        }
    } else if (strcmp(argv[1], "overflow") == 0) {
        conf.phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_OFF;
        ctx.response_body_bytes_seen = SIZE_MAX - 1U;
        ctx.response_body_bytes_inspected = SIZE_MAX - 1U;
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            2U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U && ctx.response_body_truncated);
        CHECK(ctx.response_body_bytes_seen == SIZE_MAX);
        CHECK(ctx.response_body_bytes_inspected == SIZE_MAX - 1U);
    } else if (strcmp(argv[1], "invalid-accounting") == 0) {
        ctx.response_body_bytes_inspected = 1U;
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1U, &allowed) == NGX_ERROR);
        CHECK(allowed == 0U && ctx.response_body_truncated);
        CHECK(ctx.response_body_bytes_seen == 0U);
    } else if (strcmp(argv[1], "null-empty-mode") == 0) {
        CHECK(ngx_http_modsecurity_plan_limited_response_body(NULL, &conf,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, NULL,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1U, NULL) == NGX_ERROR);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            0U, &allowed) == NGX_OK && allowed == 0U);
        CHECK(!ctx.response_body_seen);
        conf.phase4_mode = 99U;
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
    } else if (strcmp(argv[1], "file-chunks") == 0) {
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(read_calls == 3 && append_calls == 3 && read_max == 32768U);
        CHECK(allocation_calls == 1 && appended_bytes == sizeof(payload));
        CHECK(memcmp(inspected, payload, sizeof(payload)) == 0);
        CHECK(buffer.file_pos == 0 && buffer.file_last == sizeof(payload));
        buffer.file_last = 1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(allocation_calls == 1 && appended_bytes == sizeof(payload) + 1U);
    } else if (strcmp(argv[1], "mixed-once") == 0) {
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + 15;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(appended_bytes == 15U && append_calls == 1 && read_calls == 0);
        CHECK(ctx.response_body_bytes_seen == 15U);
        CHECK(buffer.pos == payload && buffer.last == payload + 15);
    } else if (strcmp(argv[1], "file-limit") == 0) {
        conf.phase4_body_limit = sizeof(payload) - 1U;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 0 && allocation_calls == 0 && append_calls == 0);
        CHECK(ctx.response_body_truncated);
    } else if (strcmp(argv[1], "file-invalid") == 0) {
        buffer.file_pos = -1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        buffer.file_pos = 10; buffer.file_last = 9;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        buffer.file_pos = 0; buffer.file_last = 10; buffer.file = NULL;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 0 && append_calls == 0);
    } else if (strcmp(argv[1], "allocation-failure") == 0) {
        fail_allocation = 1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 0 && appended_bytes == 0U);
    } else if (strcmp(argv[1], "short-read") == 0 || strcmp(argv[1], "read-error") == 0) {
        short_read = strcmp(argv[1], "short-read") == 0;
        fail_read = !short_read;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 1 && append_calls == 0 && appended_bytes == 0U);
    } else if (strcmp(argv[1], "append-error") == 0) {
        fail_append = 1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(ctx.response_body_bytes_inspected == 0U);
    } else if (strcmp(argv[1], "append-zero") == 0) {
        append_result = 0;
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(ctx.response_body_bytes_inspected == 10U && append_calls == 1);
    } else if (strcmp(argv[1], "final-once") == 0) {
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_OK);
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_OK);
        CHECK(process_calls == 1 && pcre_enter == 1 && pcre_leave == 1);
        CHECK(ctx.phase4_processed);
    } else if (strcmp(argv[1], "engine-error") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); conf.phase4_mode = (unsigned)i;
            request.header_sent = 1; connection.error = 0; engine_result = -1;
            CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_ERROR);
            CHECK(ctx.phase4_processed && ctx.intervention_triggered && connection.error);
        }
        CHECK(process_calls == 3 && pcre_enter == pcre_leave);
    } else if (strcmp(argv[1], "process-zero") == 0) {
        engine_result = 0;
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == 500);
        CHECK(ctx.intervention_triggered && ctx.phase4_processed);
        CHECK(process_calls == 1 && pcre_enter == pcre_leave);
    } else if (strcmp(argv[1], "main-eos") == 0 || strcmp(argv[1], "subrequest-eos") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; buffer.last_in_chain = 1;
        chain.next = NULL;
        if (strcmp(argv[1], "subrequest-eos") == 0) request.main = &main_request;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(appended_bytes == 10U && process_calls == (request.main != &request));
        chain.buf = &final; final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && appended_bytes == 10U);
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && forward_calls == 3);
    } else if (strcmp(argv[1], "chain-restored") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(chain.next == &tail && tail.next == NULL);
        CHECK(forward_calls == 1 && forwarded_links == 2 && process_calls == 1);
        CHECK(appended_bytes == 10U && buffer.pos == payload);
    } else if (strcmp(argv[1], "forward-again") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; final.last_buf = 1;
        forward_result = NGX_AGAIN;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_AGAIN);
        CHECK(chain.next == &tail && forwarded_links == 2 && process_calls == 1);
        CHECK(buffer.pos == payload && appended_bytes == 10U);
        forward_result = NGX_OK;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(forwarded_links == 4 && appended_bytes == 10U && process_calls == 1);
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_OK);
        CHECK(process_calls == 1 && chain.next == &tail);
    } else if (strcmp(argv[1], "terminal-trailing") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; buffer.last_buf = 1;
        final.memory = 1; final.pos = payload + 10; final.last = payload + 20;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && appended_bytes == 10U);
        CHECK(chain.next == &tail && forwarded_links == 2);
    } else if (strcmp(argv[1], "replaced-body") == 0) {
        ctx.response_replaced = 1;
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + 10;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(buffer.pos == buffer.last && !buffer.in_file);
        CHECK(buffer.file_last == buffer.file_pos);
        CHECK(append_calls == 0 && process_calls == 0 && forwarded_links == 2);
    } else if (strcmp(argv[1], "late-safe") == 0 || strcmp(argv[1], "late-strict") == 0 || strcmp(argv[1], "late-off") == 0) {
        request.header_sent = 1; native_result = -1; native_late = 1;
        ctx.last_intervention_status = 403;
        if (strcmp(argv[1], "late-off") == 0) conf.phase4_mode = 0;
        if (strcmp(argv[1], "late-strict") == 0) conf.phase4_mode = 2;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) ==
            (conf.phase4_mode == 1 ? NGX_OK : NGX_ERROR));
        CHECK(event_calls == (conf.phase4_mode != 0));
        CHECK(ctx.intervention_triggered == (conf.phase4_mode != 1));
        if (conf.phase4_mode == 1) CHECK(strcmp(last_action, "log_only") == 0);
        if (conf.phase4_mode == 2) {
            CHECK(strcmp(last_action, "connection_abort") == 0);
            CHECK(ctx.phase4_strict_abort && connection.error);
        }
    } else if (strcmp(argv[1], "native-failure-safe") == 0) {
        request.header_sent = 1; native_result = 500; native_failed = 1;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == NGX_ERROR);
        CHECK(connection.error && ctx.intervention_triggered && event_calls == 0);
    } else if (strcmp(argv[1], "native-failure-uncommitted") == 0) {
        native_result = 500; native_failed = 1;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == 500);
        CHECK(ctx.intervention_triggered && event_calls == 0);
    } else if (strcmp(argv[1], "uncommitted-deny") == 0) {
        native_result = 403; ctx.last_intervention_status = 403;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == 403);
        CHECK(ctx.intervention_triggered && event_calls == 1);
        CHECK(strcmp(last_action, "deny_status") == 0);
        CHECK(strcmp(last_reason, "response_not_committed") == 0);
    } else if (strcmp(argv[1], "log-failure-safe") == 0) {
        request.header_sent = 1; native_result = -1; native_late = 1; log_result = NGX_ERROR;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == NGX_ERROR);
        CHECK(ctx.intervention_triggered && connection.error);
    } else {
        return 2;
    }
    return 0;
}
"""


def unit_program(body: str) -> str:
    functions = (
        "response_body_failure", "plan_limited_response_body",
        "append_response_body_chunk", "append_limited_response_body",
        "append_file_response_body", "append_response_body_buffer",
        "phase4_handle_intervention", "process_response_intervention",
        "process_final_response_body",
    )
    production = "".join(
        "\nstatic ngx_int_t\n" + function_definition(body, "ngx_http_modsecurity_" + name)
        + "\n" for name in functions
    )
    production += "\nstatic void\n" + function_definition(
        body, "ngx_http_modsecurity_discard_replaced_response_body"
    )
    production += "\nngx_int_t\n" + function_definition(
        body, "ngx_http_modsecurity_body_filter"
    )
    return PREAMBLE + production + CASES


class Phase4RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        directory = tempfile.TemporaryDirectory(prefix="nginx-phase4-")
        cls.addClassCleanup(directory.cleanup)
        source = Path(directory.name) / "phase4.c"
        cls.binary = Path(directory.name) / ("phase4.exe" if os.name == "nt" else "phase4")
        source.write_text(unit_program(BODY.read_text(encoding="utf-8")), encoding="utf-8")
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if build.returncode:
            raise AssertionError("Phase4 helper compilation failed:\n" + build.stderr)

    def run_case(self, name: str) -> None:
        result = subprocess.run(
            [str(self.binary), name], capture_output=True, text=True,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def case_test(name: str):
    def test(self: Phase4RuntimeTests) -> None:
        self.run_case(name)
    return test


for case in (
    "off-large", "off-multiple", "budget-boundary", "oversized-first",
    "overflow", "invalid-accounting", "null-empty-mode", "file-chunks",
    "mixed-once", "file-limit", "file-invalid", "allocation-failure",
    "short-read", "read-error", "append-error", "append-zero", "final-once",
    "engine-error", "process-zero",
    "main-eos", "subrequest-eos", "chain-restored", "forward-again",
    "terminal-trailing", "replaced-body",
    "late-safe", "late-strict", "late-off", "native-failure-safe",
    "native-failure-uncommitted", "uncommitted-deny", "log-failure-safe",
):
    setattr(Phase4RuntimeTests, "test_" + case.replace("-", "_"), case_test(case))


if __name__ == "__main__":
    unittest.main()
