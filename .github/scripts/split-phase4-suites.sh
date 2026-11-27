#!/bin/sh

# Split the connector suites in the current nginx-tests directory for CI:
# phase4-suites.txt lists the modsecurity*.t suites named in
# PHASE4_PENDING_SUITES, which need the Phase 4 source changes of #377 and
# run without blocking the job; blocking-suites.txt lists all others.
# Each list is one line, so cmd can read it with "for /f" as well.
set -eu

blocking=
pending=
for suite in modsecurity*.t; do
    case " ${PHASE4_PENDING_SUITES:-} " in
    *" $suite "*) pending="$pending $suite" ;;
    *) blocking="$blocking $suite" ;;
    esac
done

printf '%s\n' "${blocking# }" > blocking-suites.txt
printf '%s\n' "${pending# }" > phase4-suites.txt
echo "Blocking suites:$blocking"
echo "Phase 4 suites, not blocking:$pending"
