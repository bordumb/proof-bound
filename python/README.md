# Python adapter helper

`proofbound.protocol` implements only the closed, canonical JSON subprocess
envelope used by Python adapters. It does not load Proofbound manifests,
evaluate trust policy, or derive claim status; those remain the Rust CLI's
single authority.

Both request and response parsers reject unknown fields, non-canonical JSON,
invalid identities, and failed responses that attempt to smuggle evidence.
