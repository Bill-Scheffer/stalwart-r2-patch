#!/usr/bin/env bash
# An e2e check must FAIL on an image that still has the bug, or its pass on the new image proves nothing.
# usage: previous-must-fail.sh <bug-reference image, tag@digest> <e2e script> <bug line>...
# Every bug line given must appear in the output, and at least one must be given. The reference is plain upstream at
# the same release (build.yml's UPSTREAM_IMAGE), never "the image running now": that has the patches, so it passes the
# check and this step rightly refuses it. (Until MAI-1441 each patch had its own fixed 0.16 image, the build before it.)
#
# It must fail FOR THE BUG, not for any reason. Before this script the build step pulled
# "${STALWART_TAG}-${PREVIOUS}" without `set -e`: on a new Stalwart release that image does not exist, the pull
# failed silently, the e2e then failed on a missing image, and the step counted that as "the bug reproduced": it
# passed having measured nothing. So: the pull must succeed, and the e2e must fail on the one check the bug breaks.
set -uo pipefail
IMG=${1:?usage: $0 <bug-reference image> <e2e script> <bug line>...}
E2E=${2:?usage: $0 <bug-reference image> <e2e script> <bug line>...}
# The lines the bug produces (each e2e's check() prints "PASS <msg>" or "FAIL <msg>").
BUGS=("${@:3}")
[ ${#BUGS[@]} -gt 0 ] || { echo "::error::name the bug lines the check must print on $IMG"; exit 1; }
docker pull -q "$IMG" >/dev/null || { echo "::error::cannot pull the bug-reference image $IMG: nothing to compare against"; exit 1; }
OUT=$(bash "$E2E" "$IMG" 2>&1); rc=$?
printf '%s\n' "$OUT"
[ "$rc" -ne 0 ] || { echo "::error::$(basename "$E2E") PASSED on $IMG: it proves nothing (is the reference a bug-free build?)"; exit 1; }
for BUG in "${BUGS[@]}"; do
  grep -qxF "$BUG" <<<"$OUT" || { echo "::error::the check failed on $IMG, but NOT on the bug: no line '$BUG' (exit $rc): a broken harness, not a reproduction"; exit 1; }
done
echo "ok: the check fails on $IMG for the bug itself (${#BUGS[@]} line(s))"
