# Trusted transcription template

Use this template when typed values are produced outside a theorem boundary
but a registered, deterministic transcriber and re-encoder can establish one
exact external round trip.

The evidence unit is intentionally closed: its only inputs are the source, the
committed typed transcription, and the Python driver; its inventory is exactly
the two audited artifacts; it has no committed outputs or free-form operation
arguments. The adapter generates a fresh candidate, compares it byte-for-byte
with `transcribed/values.json`, and re-encodes that fresh candidate back to the
exact source.

`PATH` is the sole environment exception needed to resolve `python3`; its value
is hashed in provenance and the resolved interpreter identity is recorded.

Replace both format implementations together, retain the exact
`proofbound-transcription-driver/1` command interface, then update the claim,
paths, and format IDs. The driver is trusted in two distinct derived TCB roles.
This route yields `TRANSCRIBED`; it is never a theorem, artifact binding, or
source refinement.
