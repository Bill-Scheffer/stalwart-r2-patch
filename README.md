# stalwart-r2-patch

[Stalwart](https://github.com/stalwartlabs/stalwart) built from its own release source with **nine**
changes: it can delete blobs from **Cloudflare R2**, **sharing never crosses tenants**, stored files
and mail written into a mailbox are **scanned**, a ban that expired is **enforced again**, a narrow
key **cannot take over an Admin**, an operator can run **admin verbs on a mailbox without reading
its mail**, and calendar mail carries **no Stalwart logo**.

## The problem

Stalwart's S3 blob store uses the [`rust-s3`](https://github.com/durch/rust-s3) crate. Its
`DeleteObject` signs `Content-Length` and `Content-Type` headers that the HTTP client never sends.
R2 validates SigV4 strictly, rebuilds a different canonical request, and rejects every delete with
`403 SignatureDoesNotMatch`. Deleted mail then stays in the bucket forever.

- rust-s3 issue: [#466](https://github.com/durch/rust-s3/issues/466)
- rust-s3 fix, open: [#467](https://github.com/durch/rust-s3/pull/467) (+10 lines, one file)
- Stalwart issue: [#3185](https://github.com/stalwartlabs/stalwart/issues/3185)

Reproduced on Stalwart v0.16.24 against R2, and the fix confirmed: a client built exactly like
Stalwart's (`Region::Custom`, path-style) got `403 SignatureDoesNotMatch` with rust-s3 0.37.2 and
`204` (object gone) with the PR commit.

## The change

[`build.yml`](.github/workflows/build.yml) checks out Stalwart at the release **commit**, appends
one `[patch.crates-io]` entry pointing `rust-s3` at the PR commit, and builds with Stalwart's own
`Dockerfile` and feature set. The workflow fails unless only `Cargo.toml` and `Cargo.lock` changed,
`rust-s3` is still version 0.37.2, and no other package moved.

Image: `ghcr.io/bill-scheffer/stalwart-r2-patch:<stalwart tag>-rusts3-505aded`. Pin it by digest.

## The second change: sharing stays inside a tenant

On v0.16.24, a user can grant another account access to their mailbox, calendar, address book or
files, through JMAP `shareWith` or IMAP `SETACL`, and Stalwart checks only that the grantee
exists somewhere on the server. With one tenant per customer, that lets a user share with a
different customer. The JMAP directory (`Principal/query`, `Principal/get`) already limits
everything to the caller's tenant; these two paths did not. This is the open
(AGPL) code, identical with or without an Enterprise licence.

[`patches/0002-tenant-scoped-sharing.patch`](patches/0002-tenant-scoped-sharing.patch) applies the
same tenant filter to the grantee in both paths. A grantee outside the tenant is refused exactly
as an account that does not exist, so it confirms nothing. The workflow applies it after the
rust-s3 step and fails unless the changed files are exactly rust-s3's two plus the patch's seven,
and the source diff is the patch, byte for byte.

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
`x:AppPassword` get, update and destroy (revoking stays on `x:Account`, under 0007). A script set this
way can `redirect` future mail, and an issued app password signs in to the mailbox: neither is more than
`sysAccountUpdate` already gives (it can set the mailbox's password), which is why the predicate requires it.
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
and accounts beyond the key's grant are refused while a User is still updated and destroyed. Against the last image before 0007 and 0008 it fails 27 checks
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

Image: `ghcr.io/bill-scheffer/stalwart-r2-patch:<stalwart tag>-rusts3-505aded-tenantacl2-filescan3-banexpiry1-grant1-verbs1-nologo1`.

## When this goes away

Each change goes away on its own: rust-s3 when a Stalwart release ships a `rust-s3` with the fix,
the sharing patch when upstream scopes sharing to the tenant (reported upstream). When both are
upstream, use the upstream image again and archive this repository.

## Licence

Stalwart is licensed under the AGPL-3.0; this build is offered with its complete corresponding
source: upstream's tagged release plus the changes above, which are the whole of this repository.
