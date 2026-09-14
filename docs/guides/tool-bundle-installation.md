# Install a Proofbound tool bundle

Tool bundles contain the CLI, the independent verifier, every maintained
adapter executable, and the complete public schema inventory. They support
Linux `x86_64` and `aarch64` hosts.

Download these four files for the required platform from the same approved
Proofbound workflow run:

- `proofbound-tools-<source-revision>-linux-<architecture>.tar.gz`;
- `TOOL-BUNDLE-MANIFEST.json`;
- `install-proofbound-tools.py`; and
- `SHA256SUMS`.

Verify the downloaded installer and archive against `SHA256SUMS` before the
installer runs. For example:

```console
$ sha256sum --check SHA256SUMS
$ revision=0123456789abcdef0123456789abcdef01234567
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

The source revision, successful verification-run identity, platform,
toolchain, and every payload digest are in `TOOL-BUNDLE-MANIFEST.json`. The
product label is informational metadata only. It is not a compatibility
promise or release selector. A matching digest identifies bytes. It does not
authenticate the publisher before Proofbound adopts a signing policy.

Proofbound Runtime must pin the exact source revision, verification-run
identity, platform, and archive digest. It must not select a bundle by a moving
branch, product label, version range, or latest-release URL.
