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
| Sustained question spanning several experiments | `docs/research/` (still non-normative) |
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
| [Distribution wedge](distribution-wedge.md) | exploring | 2026-09-01 | Product vision Phase 4 | Firsthand FOSDEM and Local-First demand signals, the two-audience pitch split, and the CFP-dated path to the first external receipt verification. |
| [First-hour experience](first-hour-experience.md) | active | 2026-09-01 | Spec 0001 revision (§12.2, §12.3) and a release-layout ADR | Ranked, acceptance-tested plan for the five fixes that gate a stranger's first hour, from install to error localization. |
| [Language support](language-support.md) | promoted | 2026-09-01 | Specifications 0002 and 0003 | Separate Proofbound's language-neutral assurance model from its supported evidence adapters; its Python and TypeScript plans now live in the ecosystem specifications. |
| [Proofbound language](proofbound-language.md) | exploring | 2026-09-01 | Research plan, then an ADR or dedicated language specification | Explore a native high-assurance programming language that shares Proofbound's semantic kernel, with existing-language Proofbound as its adoption bridge. |

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
