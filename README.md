# stalwart-r2-patch

[Stalwart](https://github.com/stalwartlabs/stalwart) built from its own release source with **one**
change, so that it can delete blobs from **Cloudflare R2**.

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

## When this goes away

As soon as a Stalwart release ships a `rust-s3` that includes the fix, use the upstream image
again and archive this repository.

## Licence

Stalwart is licensed under the AGPL-3.0; this build is offered with its complete corresponding
source: upstream's tagged release plus the change above, which is the whole of this repository.
