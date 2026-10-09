#!/usr/bin/env bash
# scripts/previous-must-fail.sh against stand-ins for docker and the e2e: it passes ONLY when the previous image
# is pulled and the e2e fails on the bug's own line. Run: bash tests/previous-must-fail.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); S="$HERE/../scripts/previous-must-fail.sh"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir "$W/bin"; printf '#!/bin/sh\n[ "$PULL" = ok ]\n' > "$W/bin/docker"; chmod +x "$W/bin/docker"
e2e() { printf '#!/bin/sh\nprintf "%%s\\n" "%s"\nexit %s\n' "$1" "$2" > "$W/e2e.sh"; }
BUGLINE='FAIL one more failure: the address is banned AGAIN and the ban is ENFORCED'
fail=0
t() { local want=$1 name=$2; shift 2; PATH="$W/bin:$PATH" PULL=$PULL bash "$S" img:prev "$W/e2e.sh" "$@" >"$W/out" 2>&1; local got=$?
  if { [ "$want" = pass ] && [ $got -eq 0 ]; } || { [ "$want" = fail ] && [ $got -ne 0 ]; }; then echo "ok   $name"; else echo "FAIL $name (exit $got)"; sed 's/^/     /' "$W/out"; fail=1; fi; }
PULL=ok;  e2e "$BUGLINE" 1;                  t pass "the bug-reference image fails the check on the bug's line"
PULL=bad; e2e "$BUGLINE" 1;                  t fail "⛔ the reference cannot be pulled (the old fail-open on a new release)"
PULL=ok;  e2e "PASS all good" 0;             t fail "⛔ the reference was bumped by mistake to a bug-free build: the check passes on it"
PULL=ok;  e2e "FAIL before any failure, alice signs in" 1; t fail "the check fails, but not on the bug (a broken harness)"
PULL=ok;  e2e "Error: no such image" 125;    t fail "the e2e cannot even start"
# Named bug lines (the admin-verbs check): every one must appear.
L1='FAIL 0007: the key cannot destroy an Admin'; L2='FAIL forward proof: carol got NO copy: the forward stopped'
PULL=ok;  e2e "$L1"$'\n'"$L2" 1;            t pass "named lines: the reference fails on both" "$L1" "$L2"
PULL=ok;  e2e "$L1" 1;                       t fail "named lines: one of them is missing" "$L1" "$L2"
PULL=ok;  e2e "$BUGLINE" 1;                  t fail "named lines: the default ban line does not stand in for them" "$L1"
[ $fail = 0 ] && echo PASS || { echo FAILED; exit 1; }
