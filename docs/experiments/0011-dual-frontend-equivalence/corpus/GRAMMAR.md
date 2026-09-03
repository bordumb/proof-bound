# Frozen frontend grammar and normalization

This document fixes the experiment's accepted source languages and canonical
projection before compiler implementation. It is research syntax, not a
production Proofbound language specification.

## Canonical programme

All frontends project to `proofbound-research-frontend-programme/1` with four
fields: `schema`, `project`, `claims`, and `evidence`. `project` contains exact
`id` and `ecosystem`. Claims and evidence retain every value in the registered
TOML files.

Normalization is closed:

1. object keys use canonical JSON lexical order;
2. claims and evidence are sorted by `id` and reject duplicate IDs;
3. the following arrays are strict lexical sets and reject duplicate values:
   `evidence`, `assumptions`, `premises`, `open_obligations`, `out_of_scope`,
   `source_roots`, `foundational_axioms`, `claims`, `expected_inventory`,
   `inputs`, `outputs`, `environment_allowlist`, `paths`, and `plugins`;
4. `ordering_key` and Cargo command `targets` retain order; all other selected
   operation targets are lexical sets;
5. absent claim set fields and evidence `assumptions`/`outputs` become empty
   sets; absent pytest `plugins` and Cargo-test `targets` become empty sets;
6. absent optional scalar or record fields remain absent; JSON `null` is not a
   substitute; and
7. integers remain exact JSON integers. Floats, booleans, and arbitrary
   extension values are outside this corpus.

The programme identity is SHA-256 over the ASCII domain
`proofbound-research-frontend-programme/1`, one NUL byte, and canonical JSON.
The expected byte lengths and identities are fixed in `subjects.json`.

## TOML frontend

The TOML frontend accepts only the exact registered source documents and
their closed selected schemas. File identity is checked before parsing. It
does not load the root project glob or infer omitted subject documents.

The document schema and `id` determine claim versus evidence placement. TOML
table and array source order is non-semantic except for the explicitly ordered
fields above.

## Custom Proofbound DSL

The custom source is UTF-8 with LF line endings. Blank lines are ignored; no
comments, escapes outside JSON strings, imports, interpolation, or multiline
values are accepted.

```ebnf
programme  = "programme" string "ecosystem" string newline,
             { defaults | claim | evidence }, "end" newline ;
defaults   = "defaults" string newline, { assignment }, "end" newline ;
claim      = "claim" string newline, { assignment }, "end" newline ;
evidence   = "evidence" constructor string
             [ "using" string ], newline,
             { assignment }, "end" newline ;
assignment = identifier " = " json-value newline ;
```

Constructors are exactly `python-example`, `python-property`, `node-example`,
`node-property`, `rust-example`, `kani-bounded`, `rust-mutation`, and
`lean-theorem`. Each fixes the historical evidence schema, adapter, kind, and
permitted operation/detail types. A source cannot override those fields.

A `defaults` block contains evidence fields only. `using` copies that block
before explicit fields are applied; redefining an inherited field is rejected
rather than silently overriding it. Defaults cannot refer to other defaults.
All names are unique and must be declared before use. JSON values are decoded
strictly: duplicate object keys, trailing data, non-integer numbers, and lone
surrogates reject.

The formatter emits the same declaration order as source, lexical assignment
keys, compact canonical JSON values, one blank line between declarations, and
one final LF. Formatting twice must be byte-idempotent.

## Pkl frontend

`Schema.pkl` is the sole template. Each project module must contain exactly
one `amends "Schema.pkl"` clause and no import, dynamic import, package,
project-package, glob, read, external property, or command construct. The
source and template identities are registered separately.

Evaluation uses the exact Pkl 0.32.1 executable registered in the
preregistration, an empty inherited environment except the fixed executable
search path, `--allowed-modules pkl:,file:`, `--allowed-resources ^$`, the
corpus as `--root-dir`, `--no-cache`, `--color never`, and a ten-second
timeout. A pre-evaluation lexical dependency check limits file modules to the
registered source and `Schema.pkl`; `--root-dir` alone is not treated as an
exact dependency declaration.

Pkl's JSON renderer omits nullable properties. The common normalizer then
applies the same explicit defaults and set rules as the other frontends.

## Source mapping

A semantic leaf is a project property, one claim/evidence declaration header,
or one normalized field binding; a collection is one field binding rather
than one leaf per element. Every leaf has one mapping entry with frontend,
registered source identity, and a nonempty half-open UTF-8 byte span within
that source. Several leaves may legitimately originate from one defaults or
typed-constructor span, but a leaf may not have multiple entries.

Implicit schema/adapter/kind values map to their declaration constructor.
Expanded defaults map to the original defaults assignment. Pkl values obtained
through a local binding map to the binding expression, while the consuming
declaration is retained as a separate dependency edge. The independent
checker validates bounds, exact source bytes, leaf coverage, and compilation
identity without evaluating the original frontend.

## Assignment-count metric

A semantic assignment is one scalar literal in an explicit semantic value.
Scalar elements of arrays and nested records count individually. Field names,
punctuation, comments, declaration IDs, constructor names, helper names,
references to already-counted bindings, and the Pkl `amends` URI do not count.
Fixed constructor fields therefore count at their shared type definition, not
at each use; the shared `Schema.pkl` cost is reported separately and excluded
from per-project reduction.

For TOML, the count is the number of scalar leaves in the parsed documents.
For the custom DSL, it is the number of scalar leaves in assignment JSON
values. For Pkl, it is the number of string, integer, Boolean, or null literals
in semantic property/list positions after excluding the amends URI and values
inside comments. The corpus uses no interpolation or multiline strings, so
the lexical and AST counts coincide. Expected counts are frozen in
`metrics.json`.
