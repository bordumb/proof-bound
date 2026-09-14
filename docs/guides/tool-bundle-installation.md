# Install a Proofbound tool bundle

Tool bundles contain the CLI, the independent verifier, every maintained
adapter executable, and the complete public schema inventory. They support
Linux `x86_64` and `aarch64` hosts.

Select one independently approved exact source revision. Download the closed
asset set from its public source-identity release. No cross-repository token is
required. The release contains:

- one archive and one detached manifest for each supported platform;
- `install-proofbound-tools.py`; and
- `TOOL-BUNDLE-PUBLICATION.json`; and
- `SHA256SUMS`.

Download and verify the exact closed set before the installer runs. For
example:

```console
$ repository=bordumb/proof-bound
$ revision=0123456789abcdef0123456789abcdef01234567
$ tag="proofbound-tools-${revision}"
$ public_root="https://github.com/${repository}/releases/download/${tag}"
$ curl --fail --location --remote-name "${public_root}/SHA256SUMS"
$ while read -r digest name; do
    test -n "$digest"
    curl --fail --location --remote-name "${public_root}/${name}"
  done < SHA256SUMS
$ sha256sum --check SHA256SUMS
$ archive="proofbound-tools-${revision}-linux-x86_64.tar.gz"
$ digest=$(sha256sum "$archive" | cut -d ' ' -f 1)
$ python3 install-proofbound-tools.py \
    --archive "$archive" \
    --sha256 "$digest" \
    --destination "$HOME/.local/bin"
```

The installer checks the digest again before it parses the archive. It then
checks the closed manifest, platform, exact inventory, file types, modes,
sizes, and member digests. It refuses to replace an existing executable. Use
`--replace` only after you have reviewed the new bundle identity.

Confirm both trust boundaries are available:

```console
$ proofbound --version
$ proofbound-verify --version
```

The producer repository, source revision, successful verification-run
identity, producing bundle-workflow run, tag, and public asset identities are
in `TOOL-BUNDLE-PUBLICATION.json`. Each platform manifest contains its
platform, toolchain, and payload digests. The product label is informational
metadata only. GitHub immutable-release enforcement locks the exact
source-identity tag and assets after publication. The tag is not a product
version, moving channel, or release selector. A matching digest identifies
bytes. The GitHub HTTPS channel authenticates the repository under GitHub and
repository-access controls; the assets do not yet carry an independent
signature.

Publication fails before tag creation when immutable releases are not enabled.
An uncertain publish response requires operator inspection and never permits
automatic deletion of a release that GitHub might already have made immutable.

Proofbound Runtime must pin the exact source revision, verification-run
identity, platform, and archive digest. It must not select a bundle by a moving
branch, product label, version range, or latest-release URL.
