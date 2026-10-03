# Tests

Those are nginx test files. You can copy those files into yours nginx test
tree, to perform the tests using the "prove" utility.

For more information about those tests, read the subsection "Testing your
patch" on the project's README file.

For more about nginx tests, check their repository:
http://hg.nginx.org/nginx-tests/

## Standalone Phase4 helper regressions

Run from the repository root with Python 3 and GCC or Clang:

```sh
CC=gcc python3 tests/test_phase4_runtime.py -v
CC=clang python3 tests/test_phase4_runtime.py -v
```

The suite compiles the production body-filter functions with small NGINX and
libModSecurity doubles. It checks mode-aware byte limits, overflow, memory/file
buffers, bounded file reads and allocation/read errors, finalization at EOS,
native failures, late interventions, and downstream `NGX_AGAIN`. It needs no
Common connector library. These are helper behavior tests; they do not replace
the native HTTP integration tests.

## Native Phase4 integration tests

Copy `tests/*.t` and `tests/*.pl` into an nginx-tests checkout after building
NGINX with this connector and libModSecurity. From that checkout, run:

```sh
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity-phase4-*.t
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity*.t
```

The Phase4 suites cover `off` (the default), `safe`, and `strict`, JSON event
logging, engine-owned `SecResponseBodyMimeType` selection, complete response
delivery above the optional connector budget in `off`, and budget rejection
in `safe`/`strict`. They also reject the removed `minimal` mode and connector
MIME directive. Late deny/redirect assertions check transport interruption,
because headers have already been committed; they do not promise a clean 403.

A separate GitHub workflow job runs the standalone suite immediately with
both Linux compilers, independently of the libModSecurity build. The native
Perl suites run in the Linux and Windows build jobs.

## Standalone Phase4 helper regressions

Run from the repository root with Python 3 and GCC or Clang:

```sh
CC=gcc python3 tests/test_phase4_runtime.py -v
CC=clang python3 tests/test_phase4_runtime.py -v
```

The suite compiles the production body-filter functions with small NGINX and
libModSecurity doubles. It checks mode-aware byte limits, overflow, memory/file
buffers, bounded file reads and allocation/read errors, finalization at EOS,
native failures, late interventions, and downstream `NGX_AGAIN`. It needs no
Common connector library. These are helper behavior tests; they do not replace
the native HTTP integration tests.

## Native Phase4 integration tests

Copy `tests/*.t` and `tests/*.pl` into an nginx-tests checkout after building
NGINX with this connector and libModSecurity. From that checkout, run:

```sh
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity-phase4-*.t
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity*.t
```

The Phase4 suites cover `off` (the default), `safe`, and `strict`, JSON event
logging, engine-owned `SecResponseBodyMimeType` selection, complete response
delivery above the optional connector budget in `off`, and budget rejection
in `safe`/`strict`. They also reject the removed `minimal` mode and connector
MIME directive. Late deny/redirect assertions check transport interruption,
because headers have already been committed; they do not promise a clean 403.

A separate GitHub workflow job runs the standalone suite immediately with
both Linux compilers, independently of the libModSecurity build. The native
Perl suites run in the Linux and Windows build jobs.
