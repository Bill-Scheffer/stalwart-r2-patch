#!/usr/bin/env bash
# An e2e check must FAIL on an image that still has the bug, or its pass on the new image proves nothing.
# usage: previous-must-fail.sh <bug-reference image, tag@digest> [e2e script [bug line...]]
# With no bug lines it is the ban-expiry check and its line. Every bug line given must appear in the output.
# The reference is FIXED (build.yml's BAN_BUG_REFERENCE_IMAGE, the last build before 0006), never "the image running
# now": every build after 0006 lacks the bug, so it passes the check and this step rightly refuses it.
#
# It must fail FOR THE BUG, not for any reason. Before this script the build step pulled
# "${STALWART_TAG}-${PREVIOUS}" without `set -e`: on a new Stalwart release that image does not exist, the pull
# failed silently, the e2e then failed on a missing image, and the step counted that as "the bug reproduced": it
# passed having measured nothing. So: the pull must succeed, and the e2e must fail on the one check the bug breaks.
set -uo pipefail
IMG=${1:?usage: $0 <bug-reference image> [e2e script]}
E2E=${2:-$(dirname "$0")/e2e-ban-expiry.sh}
# The lines the bug produces (each e2e's check() prints "PASS <msg>" or "FAIL <msg>").
BUGS=("${@:3}")
[ ${#BUGS[@]} -gt 0 ] || BUGS=('FAIL one more failure: the address is banned AGAIN and the ban is ENFORCED')
docker pull -q "$IMG" >/dev/null || { echo "::error::cannot pull the bug-reference image $IMG: nothing to compare against"; exit 1; }
OUT=$(bash "$E2E" "$IMG" 2>&1); rc=$?
printf '%s\n' "$OUT"
[ "$rc" -ne 0 ] || { echo "::error::$(basename "$E2E") PASSED on $IMG: it proves nothing (is the reference a bug-free build?)"; exit 1; }
for BUG in "${BUGS[@]}"; do
  grep -qxF "$BUG" <<<"$OUT" || { echo "::error::the check failed on $IMG, but NOT on the bug: no line '$BUG' (exit $rc): a broken harness, not a reproduction"; exit 1; }
done
echo "ok: the check fails on $IMG for the bug itself (${#BUGS[@]} line(s))"
