# stalwart-r2-patch

[Stalwart](https://github.com/stalwartlabs/stalwart) built from its own release source with **fourteen**
changes: **sharing never crosses tenants**, stored files
and mail written into a mailbox are **scanned**, a ban that expired is **enforced again**, a narrow
key **cannot take over an Admin**, an operator can run **admin verbs on a mailbox without reading
its mail**, calendar mail carries **no Stalwart logo**, a burst of large uploads or messages is **refused, not an OOM**, the spam filter reads a
**bounded start** of each message's text, a two-step code is **accepted once**, and a bounce returns the original's
headers **as `text/rfc822-headers`**, **up to 64 KiB** of them, none dropped for a byte that is not UTF-8, and each
account has **its own spam level**. The first change, deleting blobs from **Cloudflare R2**, is upstream's own since
v0.16.26 (below).

## The problem

Stalwart's S3 blob store uses the [`rust-s3`](https://github.com/durch/rust-s3) crate. Its
`DeleteObject` signs `Content-Length` and `Content-Type` headers that the HTTP client never sends.
R2 validates SigV4 strictly, rebuilds a different canonical request, and rejects every delete with
`403 SignatureDoesNotMatch`. Deleted mail then stays in the bucket forever.

- rust-s3 issue: [#466](https://github.com/durch/rust-s3/issues/466)
- rust-s3 fix: [#467](https://github.com/durch/rust-s3/pull/467) (+10 lines, one file), closed as covered by `6c97cb9`, released in 0.38.0
- Stalwart issue: [#3185](https://github.com/stalwartlabs/stalwart/issues/3185)

Reproduced on Stalwart v0.16.24 against R2, and the fix confirmed: a client built exactly like
Stalwart's (`Region::Custom`, path-style) got `403 SignatureDoesNotMatch` with rust-s3 0.37.2 and
`204` (object gone) with the PR commit.

## The change, now upstream's

Up to v0.16.25, [`build.yml`](.github/workflows/build.yml) appended one `[patch.crates-io]` entry pointing `rust-s3`
at the PR commit (tags `…-rusts3-505aded-…`). rust-s3 closed the PR as covered by its own fix,
[`6c97cb9`](https://github.com/durch/rust-s3/commit/6c97cb99aa49fe49ecda0c39787b896bf21a6de0) (no generated
`Content-Length` or `Content-Type` is signed on any bodyless request; DELETE and ranged GET verified against R2), released
in rust-s3 0.38.0, and Stalwart v0.16.26 moved to 0.38.0. So the build no longer touches `Cargo.toml` or `Cargo.lock`:
it fails unless the lock names `rust-s3` 0.38.0 from crates.io and the checkout is the release commit, untouched. A
release that moves rust-s3 again fails that step, and whether the new version still signs DELETE correctly is checked
then.

⚠️ v0.16.26 also made upstream's own release builds require an x86-64-v2 CPU (`.cargo/config.toml` sets
`target-cpu=x86-64-v2`, and `main.rs` then compiles in a check that refuses to start without it). This build uses
Stalwart's `Dockerfile`, whose `RUSTFLAGS` override that config, so it stays baseline x86-64 and starts on any x86-64
VM. The build checks it on the binary: the check's message is absent from this image and present in upstream's.

Image: `ghcr.io/bill-scheffer/stalwart-r2-patch:<stalwart tag>-<VARIANT>`. Pin it by digest.

## The second change: sharing stays inside a tenant

On v0.16.24, a user can grant another account access to their mailbox, calendar, address book or
files, through JMAP `shareWith` or IMAP `SETACL`, and Stalwart checks only that the grantee
exists somewhere on the server. With one tenant per customer, that lets a user share with a
different customer. The JMAP directory (`Principal/query`, `Principal/get`) already limits
everything to the caller's tenant; these two paths did not. This is the open
(AGPL) code, identical with or without an Enterprise licence.

[`patches/0002-tenant-scoped-sharing.patch`](patches/0002-tenant-scoped-sharing.patch) applies the
same tenant filter to the grantee in both paths. A grantee outside the tenant is refused exactly
as an account that does not exist, so it confirms nothing. The workflow applies it to the release
commit and fails unless the changed files are exactly the patch's seven, and the source diff is the
patch, byte for byte.

[`scripts/e2e-tenant-sharing.sh`](scripts/e2e-tenant-sharing.sh) runs the built image (pushed only after every check passes) with two
tenants and asserts both directions: across tenants, JMAP and IMAP sharing is refused (the IMAP
refusal is identical to an unknown account's); within a tenant, both still work. Against upstream
v0.16.24 the cross-tenant checks FAIL (measured), which is what makes the test worth having.

## The third change: WebDAV sharing stays inside a tenant too

The second change assumed DAV sharing was already tenant-scoped. It is not: a WebDAV `ACL` request
on a calendar, address book or file folder resolves the grantee by name and checks no tenant (the
principal check in `crates/dav/src/common/acl.rs` is commented out upstream). Measured on the
`-tenantacl1` image: the grant to another tenant's user is stored, and that user can then read the
collection. [`patches/0003-tenant-scoped-dav-acl.patch`](patches/0003-tenant-scoped-dav-acl.patch)
applies the same tenant filter there, refusing as for a principal that does not exist. The workflow
applies it after 0002 and fails unless it changed only that one file, byte for byte. The end-to-end
script asserts both directions for all three collection types; against `-tenantacl1` its nine
cross-tenant DAV checks FAIL (measured).

## The fourth change: every stored file is scanned, and capped

Stalwart scans mail that travels over SMTP through a milter, but nothing scans a file stored through WebDAV `PUT` or JMAP
`FileNode/set`: on v0.16.24 both stored the EICAR test file and read it back unchanged, with
ClamAV attached as a milter (measured). And JMAP `FileNode/set` checks no file size at all, so a
JMAP client could store past the cap WebDAV enforces (measured: 30 MiB stored against 25 MiB).
[`patches/0004-file-writes-scanned-and-capped.patch`](patches/0004-file-writes-scanned-and-capped.patch)
adds a small clamd client (`crates/common/src/file_scan.rs`, `INSTREAM`): when
`STALWART_FILE_SCAN_CLAMD` names a clamd (`host:port`), both paths (and JMAP `FileNode/copy`, which can
replace a copied file's content with a caller's blob) stream each file to it before
storing, and refuse it if infected (WebDAV 422, so a client can tell it from a permission 403; JMAP `forbidden`) or if it could not be scanned
(WebDAV 503, JMAP `forbidden`): fail closed, as the milter is. Unset, nothing is scanned. JMAP also
gets WebDAV's file-size cap (`tooLarge`). Infected and unscanned refusals log as milter events.
[`scripts/e2e-file-scan.sh`](scripts/e2e-file-scan.sh) runs the built image beside a real clamd:
clean files stored (one of exactly 25 MiB too, so clamd's stream limit cannot refuse a legitimate file;
MainThrive's clamd allows 100 MiB), EICAR refused and absent on both paths, one byte over the cap refused
as too large on both, an EICAR replacement blob refused by `FileNode/copy`, and with clamd stopped,
uploads refused. Against `-tenantacl2` eight checks FAIL; against the first `-filescan1` build, which
missed `FileNode/copy`, that one check FAILs (both measured).

## The fifth change: mail written straight into a mailbox is scanned too

The milter sees only SMTP sessions (inbound, submission, and webmail Send, which JMAP hands to one). A
message written straight into a mailbox never passes it: IMAP `APPEND` (also how a migration imports),
JMAP `Email/import`, and a JMAP draft with an attachment all stored EICAR with the milter attached
(measured). [`patches/0005-mail-written-into-a-mailbox-scanned.patch`](patches/0005-mail-written-into-a-mailbox-scanned.patch)
scans in `email_ingest`, the one function all three (and nothing SMTP-delivered) store through when
their source is JMAP or IMAP, with 0004's clamd client: refused if infected or unscannable (fail
closed). JMAP answers `invalidEmail` with the reason (Email/import already did; drafts now do too, which
also turns a draft that fails to parse into `invalidEmail` rather than failing the whole request),
IMAP `NO [CANNOT]`. Our own operator restore (`Restore`) is not scanned. The same e2e covers all three
both ways; against `-tenantacl2-filescan2` its five mail checks FAIL (measured).

## The sixth change: a ban that expired is enforced again

With a ban period set (`authBanPeriod` and its three siblings), upstream v0.16.24 lifts the first ban
on time, but every later ban of the same address is logged (`security.authentication-ban`) and never
enforced (measured). `block_ip` `insert`s into a set that compares by address alone, so the expired
entry stays; the stored `BlockedIp` insert conflicts with the expired one and changes nothing; and a
node receiving the broadcast `insert`s the same way. Expired entries go only on a restart or
`ReloadBlockedIps`. [`patches/0006-expired-ban-replaced.patch`](patches/0006-expired-ban-replaced.patch)
replaces an expired entry in memory and on every node, and updates an expired stored one in
place (as upstream updates a conflicting spam rule); a live ban is never shortened.
All four ban kinds (auth failures, RCPT abuse, loitering, port scans) go through `block_ip`.
`scripts/e2e-ban-expiry.sh` bans, waits out a 20 s ban, earns a new one and checks it holds; it FAILS
on upstream v0.16.24 and `-tenantacl1` (measured), and the build requires it to fail on the previous
image that has the bug: `BAN_BUG_REFERENCE_IMAGE`, the last build before 0006, pinned by tag and digest and ⛔
NEVER bumped with releases (every later build lacks the bug and passes). It must fail on the bug's own check line:
`scripts/previous-must-fail.sh` refuses a reference it cannot pull, one that passes, and an e2e that fails for any
other reason (`tests/previous-must-fail.test.sh`). Before that, a new Stalwart tag made the pull fail silently and
the step passed having measured nothing.

## The seventh change: an account is written only by a caller that could have created it

Stalwart's grant rule (`can_set_permissions`, `crates/common/src/auth/permissions.rs`) checks what an account
write *grants*. It does not check *whose* account is written, and `sysAccountUpdate` applies to every account.

[`patches/0007-account-writes-within-the-callers-grant.patch`](patches/0007-account-writes-within-the-callers-grant.patch)
applies the grant rule once more, to the account **as stored**: an `x:Account` update or destroy is
refused (*"This account's permissions exceed yours."*) unless the caller holds every permission the
account has now, i.e. it could have created it. An Admin, the key's own owner, or any account with a
permission the key lacks is out of reach; an ordinary User, whose permissions a provisioning key must
hold to create one, is not. A full Admin's key holds everything, so nothing it did changes. Two call
sites: `validate_account` (every update) and the registry's destroy path.

The same rule covers group membership. Adding an account to a group, on create or update, is refused
(*"This group's permissions exceed yours."*) unless the caller holds every permission the group has.
Leaving a group needs no check.

## The eighth change: admin verbs on a mailbox, without `impersonate`

The methods an operator needs on a customer's mailbox (its Sieve scripts, which is where a forward
lives; its out-of-office; its sender identities; issuing it an app password) pass upstream's
`assert_is_member` only for the account itself, a group it belongs to, or `impersonate`. And
`impersonate` also opens every message, so the only key that could switch a forward off could also
read the mail it was forwarding.

[`patches/0008-admin-verbs-without-impersonate.patch`](patches/0008-admin-verbs-without-impersonate.patch)
lets exactly these pass for a caller that is not an owner, when it holds the method's own permission,
**`sysAccountUpdate`**, the target inside its tenant (any tenant for an untenanted caller), and passes
0007's rule on the target (one helper, `Server::can_administer_account`):

| Verb | Methods |
|---|---|
| list scripts, see which is active | `SieveScript/query`, `SieveScript/get` |
| switch a forward off or on; delete a script | `SieveScript/set` (deactivate, activate, destroy) |
| read a script's content | `GET /jmap/download/…` for a blob linked to a **SieveScript only** |
| edit a script | the caller uploads to **its own** account, then `SieveScript/validate` and `SieveScript/set update` on the target. Nothing opens the target's own uploads |
| out-of-office | `VacationResponse/get`, `VacationResponse/set` |
| sender identities | `Identity/get`, `Identity/set` |
| issue an app password | `x:AppPassword/set` **create only**, within the caller's grants (`Inherit` stays refused; at sign-in a `Replace` list is intersected with the mailbox's own permissions, so it never exceeds the mailbox) |

No JMAP method or blob path that reads mail widens: `Email*`, `Mailbox*`, `Thread`, `SearchSnippet`, `EmailSubmission*`,
`Blob/get`, `Blob/copy`, `Blob/lookup`, calendars, contacts and files keep upstream's check, and so do
`x:AppPassword` get, update and destroy (revoking stays on `x:Account`, under 0007). An issued app password signs in to the mailbox over IMAP and reads all of its mail, past and future, as a
password reset does; a script set this way can `redirect` future mail. Neither is more than `sysAccountUpdate`
already gives (it can set the mailbox's password), which is why the predicate requires it.
Two upstream behaviours are left as they are: SCIM (Enterprise-only) deletes accounts on its own path, and a
Sieve or out-of-office write is counted against the caller's tenant quota rather than the target's. Without an Enterprise licence a tenanted
account cannot hold `sysAccountUpdate` at all (Stalwart caps tenanted accounts at the user set), so the
tenant clause matters only on a licensed deployment.

[`scripts/e2e-admin-verbs.sh`](scripts/e2e-admin-verbs.sh) runs the built image production-shaped: an
untenanted Admin owns a key with exactly the API's 264 permissions ([`e2e-admin-verbs.perms`](scripts/e2e-admin-verbs.perms),
no `impersonate`). Every verb is allowed on a User and refused on an Admin and without
`sysAccountUpdate`; mail stays refused (`Email/get`, `Email/query`, `Blob/get` and a download of a mail
blob); the forward proof switches a mailbox's forward off and the next message stops reaching the
forward's target; the import credential (`Replace {authenticate, imap…}` with `expiresAt`) opens IMAP;
and accounts beyond the key's grant are refused while a User is still updated and destroyed; so is adding a User to a
group beyond it, while a group within it is still joined and a member still removed. Against the last image before 0007 and 0008 it fails 29 checks
(measured), and the build requires it to fail on both bugs' lines there.

## The ninth change: no Stalwart logo on calendar mail or the RSVP page

Every calendar invitation and reminder upstream sends carries Stalwart's logo: the compiled-in templates
(`resources/html-templates/calendar-{invite,alarm}.html`, through `include_str!`) place `<img src="{{logo_cid}}">`,
and `imip.rs` and `alarm.rs` attach the image as an inline part, falling back to the built-in
`DEFAULT_LOGO_BASE64` because the per-domain logo is Enterprise-only. The guest RSVP page draws Stalwart's SVG
logo while it tries `/logo`, also Enterprise-only. There is no setting for any of it in either edition:
Enterprise can only swap the image, never remove it.

[`patches/0009-no-logo-on-calendar-mail-and-rsvp.patch`](patches/0009-no-logo-on-calendar-mail-and-rsvp.patch)
replaces the logo row in both templates (and their `.min` builds) with a 16 px spacer, stops attaching the
image part, and removes the RSVP page's SVG and the 72 px box it sat in (`.html`, `.min`, and the `.min.gz` the
server actually serves, regenerated so Stalwart's own sync test holds). Stalwart's admin login page is left
as it is: it is not customer-facing.
[`scripts/e2e-no-logo.sh`](scripts/e2e-no-logo.sh) sends a real invitation and a real reminder (a CalDAV event
with an attendee and an email alarm) and asserts that neither carries an image part or a `cid:logo`, that
both keep their HTML (and the invitation its `text/calendar`), and that the RSVP page carries no logo SVG.
Against the last image before 0009 its five logo checks fail (measured), and the build requires them to.

## The tenth change: a server-wide budget for large uploads and messages

Upstream bounds uploads per account (4 requests at once, a pending-upload quota) and inbound SMTP per sender IP (5
new connections a second), never in sum, and holds each body in memory whole. Measured on the `-nologo1` image at
2 GiB, each from its own account (MAI-1000): a 25 MiB WebDAV `PUT` or JMAP upload costs about 26 MiB while it is in
flight, an IMAP `APPEND` of a 25 MiB message about 80 MiB, and a 25 MiB message by SMTP about 160 MiB, before any
authentication. About 70 uploads at once, or a dozen large messages from a few senders, OOM-kill the process, and every
session on it is lost (measured at a smaller limit: 16 parallel uploads killed a 512 MiB container, and all 16 failed).
[`patches/0010-server-wide-cap-on-large-bodies.patch`](patches/0010-server-wide-cap-on-large-bodies.patch) keeps
two server-wide budgets, in bytes, each body holding its share until the request or message is done with it. Bytes,
not bodies, because the size limits differ (an SMTP message may be 100 MiB, a JMAP upload 50 MB, a WebDAV file 25 MiB),
so a count would bound nothing:

- **`STALWART_MAX_LARGE_UPLOAD_MIB`**: HTTP request bodies past 1 MiB. A body that would take the budget past its
  limit: WebDAV `429` with `Retry-After: 5`, JMAP `429`. The refused body is read to its end and none of it kept, so the
  client reads the `429`: answering and closing on the unread rest reset the connection, and every refused upload in a
  64-upload burst saw a network error instead (measured on the first build).
- **`STALWART_MAX_LARGE_MESSAGE_MIB`**: messages past 5 MiB, by SMTP `DATA` or `BDAT` or by IMAP `APPEND`. Past the
  budget, SMTP drops what it holds of the message at once, reads and drops the rest, and answers `452 4.3.1`, so the
  sending server retries later; the refusal ends the transaction, so a `BDAT` pipelined after it is refused too. A
  `BDAT` chunk is counted as its bytes arrive, not as declared, so one that names a size and sends nothing holds none
  of the budget. IMAP answers `NO [UNAVAILABLE]`,
  before a synchronizing literal is sent, or after a `LITERAL+` one is read and dropped (and the rest of that command
  line with it, so none of a refused `MULTIAPPEND` runs as a command). Only an `APPEND` by a logged-in client counts,
  so a client that has not logged in cannot hold any of the budget. The threshold is higher than an upload's so ordinary
  mail is never counted: a 1 MiB message costs a few MiB.

Unset, a budget is no bound (upstream's behaviour), and the server says so on stderr at startup, as it does for a
value that is not a whole number of MiB; a budget below the largest body allowed refuses that body always. The
inbound spam filter cost ~30–40 times a `text/plain` body (an attachment ~6), which these budgets do not count: the
eleventh change bounds it. A synchronizing IMAP literal reserved its declared size when it was announced, and an HTTP
body had no read timeout: the sixteenth change closes both.
[`scripts/e2e-upload-cap.sh`](scripts/e2e-upload-cap.sh) sets 30 MiB and 110 MiB. It holds two 14 MiB uploads open at
13 MiB and checks that a third of 8 MiB, by WebDAV `PUT` and by JMAP upload from other accounts, is refused while a
small file is stored, that both store on retry once the held uploads finish, that a 25 MiB body alone still meets its
size limit (`413`), and that the budget comes back after it. Then it holds two 52 MiB SMTP messages open at 50 MiB and
checks that a third of 16 MiB by `DATA` and by `BDAT` gets `452`, that IMAP `APPEND` with either kind of literal gets
`NO [UNAVAILABLE]`, that a session's next `MAIL` after a `452` is a new message, that a pipelined `BDAT` after a
refused chunk is refused, that a `MULTIAPPEND` refused mid-way runs none of the rest of its line, and that a burst of 8
ordinary messages up to 4.5 MiB and a small `APPEND` are all accepted while the budget is full. Once it is free, the
refused message and `APPEND` are accepted on retry, two stalled pre-login literals take nothing, and a single 100 MiB
message is accepted, also while a `BDAT` that declares 94 MiB and sends nothing is open. Against `-nologo1` the refusals FAIL (measured), and the build requires that.

## The eleventh change: the spam filter analyses a bounded start of each message's text

The inbound spam filter turns every word and every space of a text part into a 224-byte token and holds them all until
the message is scored, so it costs about 40 times the text it reads (measured with Stalwart's own tokenizer: 1.86
million tokens, +397 MiB, for 10 MiB of text). By SMTP a 10 MiB `text/plain` message cost 280–466 MiB across runs on
`-bodycap1`, against 30–52 MiB by IMAP `APPEND`, which does not filter; a message under the tenth change's 5 MiB
threshold is not counted at all, so a few plain-text messages on port 25, before any authentication, could take the
pod past what the budgets imply (MAI-1077).
[`patches/0011-spam-filter-analyses-a-bounded-start-of-each-text.patch`](patches/0011-spam-filter-analyses-a-bounded-start-of-each-text.patch)
analyses the first 512 KiB of each part's text, and 1 MiB of text per message, as other filters do (SpamAssassin skips
bodies past 500 KB). Everything derived from the text reads that slice: its tokens, the URLs, emails and IPs written
in it, the rules and the classifier, in training too. An HTML part is cut on the text extracted from it, not on its
markup, so the plain and HTML alternatives of a message are cut at about the same point (each at 512 KiB of its own
text): cut on markup, a large newsletter's HTML lost text its plain twin kept, and scored `PARTS_DIFFER` (+1.0) from the
cut alone (measured on the first build). HTML markup is read up to 2 MiB per message, and what the filter takes from
tags rather than text, the links and images, is read from all of that. Markup costs 5 to 24 times itself to parse
(measured: a newsletter's table cells 5, the smallest tags with bare attributes 24). A `data:` URI's payload in a `src` or
`href`, an inline image, is not markup: it is neither read nor counted, while its header, which the analysis reads,
is. Anywhere else (text, `alt`, `title`) it is read as written, so it cannot hide words: the e2e checks that words
after a `data:` in a text node are still read (measured: on the build that skipped it everywhere, they were not). Counted, a
newsletter that opens with a 3 MiB inline image used up the read before any text and scored spam, 5.20, against 3.20
(measured on the second build); a `<head>` or `<style>` block over 2 MiB still would. An HTML part cut there has the
`<head>` and `<body>` it left open closed, so the cut never scores as unbalanced HTML. So one message costs at most
~90 MiB to analyse, whatever it holds. That is per message: messages filtered at once are bounded by the SMTP limits,
not by the tenth change's budgets. (Pyzor, when enabled, still hashes the whole message, at about 1 times its HTML.)
A message is analysed exactly as before when each part has under 512 KiB of text, the whole message under 1 MiB of
text, and its HTML under 2 MiB of markup: nearly all mail.

⚠️ **The trade: padding evades it.** Text past the cut is not seen, and that includes a URL written in it: URL
extraction reads the same tokens, not the raw body, and the e2e checks that a URL past the cut is missed, in a text
part and in an HTML part's text. (An HTML link's `href` is still read, up to 2 MiB of markup.) So a spammer who puts
512 KiB of filler before the payload hides it. Accepted because such mail is rare and conspicuous, because its
envelope, headers, sender and first 512 KiB still score, and because SpamAssassin and other filters make the same cut
for the same reason. Revisit if padded spam turns up in practice, or if a whole-body signal is needed.
[`scripts/e2e-spam-text-cap.sh`](scripts/e2e-spam-text-cap.sh) checks that an 8 MiB `text/plain` message on port 25
costs under 150 MiB while it is received, filtered and delivered (`-bodycap1`: ~460 MiB); that a URL past the first
512 KiB of a text part, of an HTML part's text, or at the start of a third part past the first 1 MiB, is not analysed,
while one early in each is; and that a control set scores exactly as on `-bodycap1`: ordinary mail small and large,
plain and HTML, a newsletter whose plain and HTML alternatives are both cut while its topics and links change, a
newsletter that opens with a 3 MiB inline image, HTML past 2 MiB of markup, unclosed HTML, and spam whose signal sits early in a 2 MiB body (a suspicious URL, a phishing link, URL
rules). The scores come from upstream's pinned rules release (v3.0.2, by hash), served on an internal network with a
DNS stub, so no score depends on the runner's network. Against `-bodycap1` the memory check and the three bound checks
FAIL and the control set passes (measured), and the build requires both.

## The twelfth change: a two-step code is accepted once

Upstream checks a two-step (TOTP) code against the account's `otpauth` URL and keeps no record of it, so the same six
digits sign in again, and confirm a password change again, until their window closes: about 60 to 90 seconds, since a
code is accepted one step either side of its own (measured on production's image, MainThrive MAI-989 and MAI-997). A
code that was seen (over a shoulder, in a phishing page, in a log) can be replayed for that long. RFC 6238 § 5.2 says a
verifier must not accept the second attempt, and `totp-rs`, which Stalwart uses, returns the matched step and documents
that refusing a second use of it is the caller's job. Stalwart discards the step.

A code reaches Stalwart in two places, both through `verify_mfa_secret_hash`: a sign-in (`/api/auth`, the login every
two-step client uses: an authorization code or a device code) and the password or two-step change
(`x:AccountPassword/set`). IMAP, SMTP, POP3, ManageSieve and HTTP Basic carry no code, so a two-step account cannot
sign in there with its password at all, only with an app password; nothing changes there. Those two are the only
callers of the verifier: an external directory (LDAP, SQL, OIDC) checks its own credentials and is not covered
(MainThrive uses none).

[`patches/0012-a-two-step-code-is-accepted-once.patch`](patches/0012-a-two-step-code-is-accepted-once.patch): the
verifier returns the matched step and how long it can still be accepted, and both callers mark (account, step) used,
with `try_lock` in the in-memory store, before they accept the code. A second use is refused: a sign-in as a failed
one (logged with the reason `TOTP code already used`; it counts towards the auth-failure ban like any other), a change
with *"This two-step code was already used. Wait for the next one."* The mark is set atomically in both backends
(Valkey `SET NX EX`; in the data store, an asserted write), so with the in-memory store in Valkey, as MainThrive runs
it, two nodes cannot both accept one code. It expires when the step can no longer be accepted. A change checks the new
password's strength before it marks the code, so a refused password does not spend it. What it does not cover: turning
two-step ON proves no code against the new secret (upstream checks only the old one, and there is none), so nothing is
marked then; and the mark is per account and step, not per secret, so a code from a secret enrolled within the same
~60 s as a code from the old one was used is refused once. With the in-memory store in the data store, 0012 adds
nothing that deletes an expired mark (one small row per two-step sign-in; Valkey expires its own).
⚠️ A webmail that signs in again after a password change with the code the change was confirmed with is refused: it must
ask for the next code (MainThrive's bulwark-client-ip `0014`).
[`scripts/e2e-totp-replay.sh`](scripts/e2e-totp-replay.sh) runs every check twice, with the in-memory store in the data
store and then in Valkey: the same code twice in one window, a code that confirmed a password change used again to sign
in, and a code already used to confirm a change, are each refused, while a fresh code, the next window's code, and a
code carried by a change refused for a too-short password all still work, and IMAP and HTTP Basic refuse the password
alone while an app password signs in. Against the last image before it (`MAI997_BUG_REFERENCE_IMAGE`) the three reuse
checks FAIL and the controls pass (measured), and the build requires both.

## The thirteenth change: a bounce returns the original's headers as `text/rfc822-headers`

A bounce (DSN) returns the original message's headers only, never its body, but upstream labels them `message/rfc822`
and lets mail-builder pick the encoding: quoted-printable whenever a header line is longer than 77 characters, which most
mail has. A relay that parses a `message/rfc822` part as a whole message refuses that. Amazon SES did, through real SES
(MainThrive MAI-1036): 554 *"Unbalanced quoted string"* for upstream's shape (a soft line break fell inside a quoted
boundary), and 554 *"Missing start boundary"* for the same headers in 7bit, since a header-only message whose
Content-Type names a multipart has no body and no boundary. It accepted `text/rfc822-headers` in 7bit, and every
header arrived byte for byte.

[`patches/0013-bounces-return-headers-as-text-rfc822-headers.patch`](patches/0013-bounces-return-headers-as-text-rfc822-headers.patch)
sends RFC 6522's `text/rfc822-headers` instead: 7bit, or 8bit when a header carries raw UTF-8, so the headers arrive as
written. Neither may carry a lone CR or LF or a NUL, and mail-builder passes those through as 7bit (upstream's bounce of
a header with a lone CR went out so, measured), so every line ends in CRLF, a lone CR included, and NULs are dropped. A
line past SMTP's 998 octets (a header that long is itself out of spec) is left to mail-builder to encode. The first
two parts are upstream's; how much of the header block is returned is the fourteenth change's. ⚠️ Only the 7bit shape was measured through
real SES (MAI-1036); an 8bit one goes out without `BODY=8BITMIME`, as Stalwart sends all 8bit mail.
[`scripts/e2e-dsn-headers.sh`](scripts/e2e-dsn-headers.sh) bounces four real messages: they are submitted to an
outside domain whose MX, a stub on an internal network found through a DNS stub, refuses the recipient with 550. One is
ASCII, with a header line past 77 characters and a multipart Content-Type; one has a raw UTF-8 Subject; one a header
line past 998 octets; one a lone CR. Each bounce's third part must be `text/rfc822-headers`: the first two in 7bit and
8bit holding the original's headers byte for byte, the third encoded by mail-builder, the fourth in 7bit with every CR
and LF a CRLF. Against production's image before it (MAI-997's branch build) seven checks FAIL (`message/rfc822`,
quoted-printable, and the lone CR sent raw in 7bit), while its controls, that each bounce arrives and its third part
carries the original's Message-ID once decoded, pass (measured). The build requires both.

## The fourteenth change: a bounce returns the original's whole header block, up to 64 KiB

Upstream reads only the first 4096 bytes of the stored message for a bounce's returned headers. A real message from Gmail
does not fit: the receiving server's own trace headers (`Received`, `Authentication-Results`, `Received-SPF`,
`X-Spam-Result`, `X-Spam-Score`, `Return-Path`, about 1.3 KB) come first, then Gmail's `Received`, ARC and DKIM blocks,
and the 4096 bytes ran out inside `X-Google-DKIM-Signature`, before the original's `From`, `Subject` and `Message-ID`.
That bounce reached Gmail with SPF, DKIM and DMARC passing, and went to Spam (measured in production, MainThrive
MAI-1127/MAI-1131).

[`patches/0014-bounces-return-the-whole-header-block.patch`](patches/0014-bounces-return-the-whole-header-block.patch)
raises the read to 64 KiB. Upstream already stops at the blank line that ends the header block, so a bounce returns the
whole block, and only that. 64 KiB is over ten times the Gmail block (5.6 KB in the e2e, 6167 B for the whole real
message) and still bounds what a pathological message makes one bounce scan and return; a block past it is cut at its
last whole line, as upstream cut at 4 KiB. (It bounds no I/O: `get_blob` fetches the whole blob whatever the range, as
it did at 4 KiB.) The same patch replaces a header byte that is not UTF-8 (U+FFFD): upstream turned the whole part into
an empty string, measured on `-dsnhdrs1` (2 bytes), and a 64 KiB block is likelier to carry one than 4 KiB.
Nothing else changes.
[`scripts/e2e-dsn-headers.sh`](scripts/e2e-dsn-headers.sh) bounces four more messages: `gmail`, with the real message's
headers in its order and sizes (trace headers, `Received`, `ARC-Seal`, `ARC-Message-Signature`,
`ARC-Authentication-Results`, `DKIM-Signature`, `X-Google-DKIM-Signature`, and the rest; random signatures, the test's
own addresses); `big`, with 5 KiB of plain headers; `huge`, whose 72 KiB of headers pass the cap; and `latin1`, with
a raw 0xE9 in a header, sent to its own recipient so its bounce is found even when the part is empty. The first two
put their `From`, `Subject` and `Message-ID` past byte 4096 (asserted), and each bounce must return them, and every
header byte for byte; `huge`'s part must stop between 60 and 64 KiB on a whole line; `latin1`'s must return its
identifying headers in 8bit with the byte replaced. Against production's image before it (`MAI1131_BUG_REFERENCE_IMAGE`)
those six checks FAIL, with `gmail`'s part cut at 4026 bytes and `latin1`'s empty, while their controls and the
thirteenth change's checks pass (measured). The build requires both.

## The fifteenth change: an account's spam level moves its Junk line

Upstream has one line for the whole server: a message is spam for a recipient when its per-recipient spam percentage
is 50 or more (with the default thresholds, a score of 5.0), and nothing changes that per account. MainThrive's
customers choose Strict, Normal or Lenient per business, domain or mailbox, and its API resolves that into one row per
account (MainThrive MAI-964's design record, § 3.2-3.3; MAI-1070).

[`patches/0015-spam-level-moves-the-junk-line.patch`](patches/0015-spam-level-moves-the-junk-line.patch) reads one
optional row at delivery, in the `spam-level` lookup namespace, keyed by the recipient account's id (its `x:Account` id,
`b`, `c`, ...), whose value is the line `L`, 1 to 99. Right after the account is resolved, and before either reader of the
percentage, it rescales the recipient's percentage `p` so that `L` maps to 50: `p < L` becomes `p × 50 / L`, `p ≥ L`
becomes `50 + (p − L) × 50 / (100 − L)` (0 stays 0 and 100 stays 100). So everything that already reads the percentage agrees
with the account's level, with nothing else taught about it: delivery's `is_spam()` (the Junk folder and keyword),
Sieve's `spamtest`, which webmail's own rules use to skip spam, contact and reply trust, and `X-Spam-Status`. No row is
Normal, unchanged, so a server with no rows behaves as upstream. Only mail the spam filter scored has a percentage, and
only that is looked up.

⛔ **It never defers mail.** An error returned there would be a temporary failure. So a lookup that fails is logged
(`Spam level lookup failed, delivering at Normal.`) and read as no row; a value that is not a whole number from 1 to 99 is
logged (`Spam level is not a number from 1 to 99, delivering at Normal.`, a `store.data-corruption` event) and read as no
row too. A namespace with no store is no row, silently: that is the ordinary state until a first row is written.

[`scripts/e2e-spam-level.sh`](scripts/e2e-spam-level.sh) delivers two scored messages, `low` (4.20, no `Date`) and `high`
(6.20, a subject in capitals), to accounts at 40, no row and 70, each with a webmail folder rule guarded as webmail guards
it, and to accounts at 40 and 70 with no Sieve script: Strict sends `low` to Junk, Lenient keeps `high` out of it, and
`X-Spam-Status` says the same. Rows of `0`, `100` and `strict` deliver at Normal and are logged. Then the namespace
becomes a Redis store nobody listens on, and a message is still delivered at once, at Normal, the failure logged.
Against production's image before it (`MAI1070_BUG_REFERENCE_IMAGE`) the four Strict and Lenient checks and the two log
checks FAIL, while Normal, the bad rows and the unavailable store pass, since it reads no level at all (measured). The
build requires both.

## The sixteenth change: a client that stops sending holds none of the budgets

The tenth change left two ways for a logged-in client to hold part of a server-wide budget without sending the bytes,
so that other customers' large messages or uploads got the retryable refusal while it waited (MainThrive MAI-1078):

- **An IMAP literal claimed its declared size at `{n}`**, before the server sent `+` and before any byte arrived, and
  held it until the IMAP timeout (30 minutes). IMAP's request limit is 50 MiB by default, so one client held up to
  ~50 MiB of the message budget and four held a 200 MiB one.
- **An HTTP body had no read timeout.** Upstream reads a request body with none, so a WebDAV `PUT` or JMAP upload that
  stopped sending kept its share of the upload budget for as long as it kept the connection open. SMTP's equivalent is
  bounded by its own timeout. An IMAP literal that stopped partway waited the session's (30 minutes).

[`patches/0016-stalled-bodies-hold-no-budget.patch`](patches/0016-stalled-bodies-hold-no-budget.patch):

- An `APPEND` literal past 5 MiB is counted as its bytes arrive, a read at a time, as `BDAT` already was. One that would
  not fit in the budget as it stands is still refused before `+`, as before, but nothing is held for it until it is
  sent. One that runs out of budget partway is dropped with what it held, the rest of it is read and dropped (the
  client was told to send it), and the command is answered `NO [UNAVAILABLE]` at its end; the session goes on. A
  `MULTIAPPEND`'s earlier literals are dropped with it, since their share goes too.
- A body holding budget that sends nothing for **`STALWART_BODY_IDLE_SECS`** (60 when unset; a value that is not a
  positive whole number of seconds is logged at startup and read as 60) is ended, and what it held goes back: an HTTP
  request with `408`, an IMAP literal with its session (`* BYE`, as the session's own timeout does). The timeout is per
  read, not for the whole body, so a slow upload that keeps sending is never ended.
- A body that keeps sending but holds budget below **16 KiB/s** on average, once past that same grace, is refused the
  same way: an HTTP request with `408`; an IMAP literal is read to its end and dropped, holding nothing, and answered
  `NO [UNAVAILABLE]`. Without it, a burst and then a byte a minute held a share at next to no bandwidth. HTTP counts
  the rate from when the body began holding budget (past 1 MiB), IMAP from the literal's first byte. ⚠️ **The trade:**
  a genuine upload slower than 16 KiB/s (0.13 Mbit/s) is refused and has to be retried (Bill, MainThrive MAI-1078).
  A fixed constant, `BODY_MIN_RATE`.
- Every HTTP body read through
  `fetch_body` has it; the management API and form bodies, whose callers know only "too large", answer as for a body
  too large.

[`scripts/e2e-stalled-bodies.sh`](scripts/e2e-stalled-bodies.sh) sets 30 MiB, 110 MiB and 5 s. Two clients declare
48 MiB literals and send nothing, and a 52 MiB message and a 40 MiB `APPEND` are accepted meanwhile. With 80 MiB then
held by two SMTP messages, one of the stalled clients sends all but 4 MiB of its literal and runs out at about 30 MiB;
once the SMTP messages finish, a 97 MiB message is accepted while it is still short of its end and the other is still
declared, so neither holds anything. Its literal is then answered `NO [UNAVAILABLE]`, and the same session's `NOOP` and
retried `APPEND` succeed. A literal that sends 30 MiB and stops gets `* BYE` after 5 s, and a 97 MiB message is accepted
before the client closes its side. A literal that sends 64 KiB and then 1 KiB every 2 s is answered `NO [UNAVAILABLE]`
once sent, and its session goes on; an HTTP body that does the same past 1 MiB gets `408`. Then two WebDAV `PUT`s stall at 13 MiB: a third upload is refused while they hold the budget, after 5 s a
WebDAV and a JMAP upload are accepted while the stalled clients are still connected, both stalled requests get `408`,
and so does a stalled JMAP upload, while a body sending 1 MiB every 3 s is stored. Against `-bodycap1`
(`MAI1077_BUG_REFERENCE_IMAGE`) each hold FAILs and the controls pass; the build requires both.

Image: `ghcr.io/bill-scheffer/stalwart-r2-patch:<stalwart tag>-tenantacl2-filescan3-banexpiry1-grant2-verbs1-nologo1-bodycap1-textcap1-totponce1-dsnhdrs1-dsnfull1-spamlevel1-stall1`.

## Builds, tags and testing a change before it merges

| What runs `build` | Checks | Pushes |
|---|---|---|
| A pull request to `main` | every check: patches, assertions, tests, the image build, every end-to-end check | **nothing**, and it never logs in to the registry |
| A push to `main`, or a dispatch on `main` | the same | the **release tag**: `<STALWART_TAG>-<VARIANT>` |
| A dispatch from any other branch | the same | **`branch-<short sha>`** only, never the release tag |

`build` is the required check on `main`, so a pull request merges only once it is green.

To run a change on the cluster before it merges (a throwaway or a window test), push the branch, then:

```bash
gh workflow run build.yml -R Bill-Scheffer/stalwart-r2-patch --ref <branch>
gh run watch -R Bill-Scheffer/stalwart-r2-patch "$(gh run list -R Bill-Scheffer/stalwart-r2-patch -w build -b <branch> -L 1 --json databaseId --jq '.[0].databaseId')"
```

The run's summary names the tag and the digest. Pin the image **by digest**
(`ghcr.io/bill-scheffer/stalwart-r2-patch@sha256:…`), never by the `branch-` tag, and replace it with the release
digest once the change merges and `main` publishes it. A branch image is never released: only `main` publishes a
release tag, and only once. A tag that already exists is never re-pushed, so a change to what is built must bump
`VARIANT`. The build fails a pull request that changes `patches/`, a value in `env:` or a step up to and
including the image build without the bump, and the digest you pin keeps its tag (MainThrive MAI-1021).

A digest pinned without a tag of its own, such as one pinned before that, is protected by tagging it
`pinned-<first 12 hex>`. The workflow copies the manifest as-is and never moves a tag:

```bash
gh workflow run protect-digest.yml -R Bill-Scheffer/stalwart-r2-patch -f digest=sha256:<64 hex>
```

## When this goes away

Each change goes away on its own: rust-s3 did, when Stalwart v0.16.26 shipped `rust-s3` 0.38.0 with the fix; the
sharing patch goes when upstream scopes sharing to the tenant (reported upstream). When every change is upstream, use
the upstream image again and archive this repository.

## Licence

Stalwart is licensed under the AGPL-3.0; this build is offered with its complete corresponding
source: upstream's tagged release plus the changes above, which are the whole of this repository.
