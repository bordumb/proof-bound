# Working notes

[Documentation map](../README.md)

This directory holds ideas that are useful enough to preserve, but are not yet
normative product behavior, an accepted architectural decision, an adoption
guide, or experimental evidence.

## Organization

Use **topic-first filenames** for living notes and record dates inside the
document. A note such as `language-support.md` should be updated
as the idea develops rather than copied into a new date-stamped file.

This is preferable to organizing all notes by date because:

- readers normally arrive with a question or subject, not a date;
- Git already preserves the chronological history of a living note;
- date-only archives tend to accumulate overlapping, contradictory snapshots;
- the repository already has chronological experiment journals where sequence
  is part of the evidence.

Use a date in the filename only when chronology is the subject of the note—for
example, a meeting record or a one-time field observation. If those become
common, keep them under `notes/journal/YYYY-MM-DD-short-title.md` rather than
mixing them with living notes.

Keep the directory flat while it has fewer than roughly 15–20 active notes.
Introduce topic directories only after the index becomes difficult to scan.
Likely future groupings are
`product/`, `architecture/`, `adapters/`, and `research/`, but creating those
categories before they contain several notes would add ceremony without
improving discovery.

## Lifecycle

Each note should begin with:

- `Status`: usually `exploring`, `active`, `promoted`, or `archived`;
- `Created` and `Last updated` dates;
- a one-sentence purpose.

Notes are deliberately non-normative. When an idea becomes authoritative,
promote it rather than letting the note quietly become a second specification:

| Content | Authoritative destination |
|---|---|
| Accepted architectural or trust-boundary decision | `docs/adr/` |
| Normative product or wire behavior | `docs/specs/` |
| User-facing procedure | `docs/guides/` |
| Pre-registered question and measured result | `docs/experiments/` |
| Audit result or independently checkable assessment | `docs/audits/` |

After promotion, retain the note only when its exploration remains useful. Mark
it `promoted` and link to the authoritative document.

## Index

| Note | Status | Last reviewed | Likely destination | Purpose |
|---|---|---|---|---|
| [Language support](language-support.md) | exploring | 2026-09-01 | Product vision and Python adoption guide | Separate Proofbound's language-neutral assurance model from its currently supported evidence adapters, and define a credible Python path. |

## Note template

```markdown
# Topic

- **Status:** exploring
- **Created:** YYYY-MM-DD
- **Last updated:** YYYY-MM-DD
- **Purpose:** One sentence explaining why this note exists.

## Summary

The current conclusion in a few sentences.

## Context

What prompted the note and which product problem it addresses.

## Current position

What is implemented, demonstrated, assumed, and still missing.

## Direction

Possible next steps, trade-offs, and promotion criteria.
```
