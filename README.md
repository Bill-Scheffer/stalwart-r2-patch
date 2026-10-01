# stalwart-r2-patch

[Stalwart](https://github.com/stalwartlabs/stalwart) built from its own release source with **two**
changes: it can delete blobs from **Cloudflare R2**, and **sharing never crosses tenants**.

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
different customer. DAV sharing and the JMAP directory (`Principal/query`, `Principal/get`)
already limit everything to the caller's tenant; these two paths did not. This is the open
(AGPL) code, identical with or without an Enterprise licence.

[`patches/0002-tenant-scoped-sharing.patch`](patches/0002-tenant-scoped-sharing.patch) applies the
same tenant filter to the grantee in both paths. A grantee outside the tenant is refused exactly
as an account that does not exist, so it confirms nothing. The workflow applies it after the
rust-s3 step and fails unless the changed files are exactly rust-s3's two plus the patch's seven,
and the source diff is the patch, byte for byte.

[`scripts/e2e-tenant-sharing.sh`](scripts/e2e-tenant-sharing.sh) runs the pushed image with two
tenants and asserts both directions: across tenants, JMAP and IMAP sharing is refused (the IMAP
refusal is identical to an unknown account's); within a tenant, both still work. Against upstream
v0.16.24 the cross-tenant checks FAIL (measured), which is what makes the test worth having.

Image: `ghcr.io/bill-scheffer/stalwart-r2-patch:<stalwart tag>-rusts3-505aded-tenantacl1`.

## When this goes away

Each change goes away on its own: rust-s3 when a Stalwart release ships a `rust-s3` with the fix,
the sharing patch when upstream scopes sharing to the tenant (reported upstream). When both are
upstream, use the upstream image again and archive this repository.

## Licence

Stalwart is licensed under the AGPL-3.0; this build is offered with its complete corresponding
source: upstream's tagged release plus the changes above, which are the whole of this repository.
