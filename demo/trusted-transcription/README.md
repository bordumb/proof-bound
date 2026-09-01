# Trusted transcription demo

This demo materializes Proofbound's deliberately degraded transcription route.
The registered Python driver parses canonical u32-line bytes into typed JSON,
then re-encodes the freshly generated candidate to the exact original bytes.
Proofbound also requires that candidate to equal the committed transcription
byte-for-byte.

The two checks form one connected execution:

```text
registered source --transcribe--> fresh typed candidate == committed typed bytes
                                      |
                                  re-encode
                                      |
                                      v
                              exact registered source
```

The result is `TRANSCRIBED`, not `PROVED`, `ARTIFACT_BOUND`, or `REFINED`.
The same driver bytes enter the TCB twice under distinct derived transcriber
and re-encoder role identities; the manifest cannot author those identities or
a round-trip Boolean.

Run the registered route from the repository root:

```sh
cargo run -q -p proofbound-cli -- check --claim DEMO-TRANSCRIPTION-001 --fresh
cargo run -q -p proofbound-cli -- claim DEMO-TRANSCRIPTION-001 --graph
```
