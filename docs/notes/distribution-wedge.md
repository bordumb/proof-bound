# Distribution wedge

[Documentation map](../README.md) · [Working notes](README.md)

- **Status:** exploring
- **Created:** 2026-09-01
- **Last updated:** 2026-09-01
- **Purpose:** Identify the communities most likely to adopt Proofbound's
  receipt and verifier first, distinguish that adoption (distribution)
  from paying demand (revenue), and attach the concrete near-term
  actions and dates.

## Summary

Two communities observed firsthand this year are already pre-sold on
Proofbound's philosophy without knowing the product exists: the
reproducibility/supply-chain crowd at FOSDEM (Brussels) and the
local-first community (Local-First Conf, Berlin). They are the
**distribution wedge** — the audiences most likely to run the
independent verifier, adopt the receipt format, and confer credibility
— and they are distinct from the **revenue wedge** (vendors under
audit pressure, per the product vision's Phase 4). The playbook is the
Sigstore / Let's Encrypt one: the open-source crowd establishes the
standard; vendors and auditors later pay for the hosted layer. The
forcing date is the FOSDEM call for participation, typically closing
late November to early December.

## Context: firsthand demand signals

- **FOSDEM 2026, Brussels.** Reproducibility was a recurring theme
  across talks — Linux kernel people, distro maintainers, WASM talks.
  FOSDEM regularly hosts a dedicated reproducible-builds devroom plus
  distributions and Rust devrooms. A decade of Reproducible Builds
  work (rebuilders, `.buildinfo` files, bit-for-bit discipline),
  sharpened by the xz-utils backdoor, has produced the *practice* of
  reproducibility without a semantic layer above it.
- **Local-First Conf 2026, Berlin.** A different audience (CRDT, sync
  engines, Ink & Switch lineage) with a different concern: trusting
  software without trusting a server. Their values — user sovereignty,
  offline verification, no service dependency — are structurally
  Proofbound's refusals.

Both rooms share the underlying itch; neither has the layer Proofbound
builds.

## The two-audience, two-pitch split

**FOSDEM pitch — "the layer above reproducibility."** The
reproducibility ecosystem answers *who built what, from which bytes*.
Receipts carry *what is known about what was built, and on what
evidence* (the paper's §8.4 framing). Rules of engagement:

- **Compose, don't compete.** Nix, Guix, and rebuilderd reproduce
  better than Proofbound's two-shadow rebuild ever will. The product
  move is an adapter that consumes rebuilder attestations as
  `independent-check` evidence — never a rival reproduction mechanism.
  (Candidate future spec; would follow the Specification 0002 §7.4
  admission-criteria pattern.)
- **The CRA angle lands hardest here.** European maintainers face
  Cyber Resilience Act obligations arriving 2027; "receipts as CRA
  technical documentation" converts latent reproducibility interest
  into a need with a date.
- **WASM components are a natural Pattern A subject** — small,
  deterministic, canonical, content-addressed bytes. Worth naming in a
  talk; not worth building before a registry carries claim metadata.

**Local-First pitch — "the verifier is a local-first trust
artifact."** `proofbound-verify` rechecks a release entirely on the
user's machine: no producer in the loop, no service, no dashboard, no
network. That is local-first ideology applied to assurance, and nobody
has claimed the framing.

## What this wedge is and is not

- It **is** the fastest route to the credibility event the whole
  roadmap points at: one stranger, on their own machine, verifying one
  receipt they did not produce.
- It **is not** revenue. These communities are volunteer-run,
  tollbooth-allergic, and institution-rich; they adopt formats and
  verifiers, they do not buy licenses. Applause here must not be
  mistaken for a market; the paying market (vendors substantiating
  claims to auditors and customers) stays the Phase 4 revenue wedge.
- The two wedges are sequential, not competing: the OSS crowd's
  adoption is what makes the vendor pitch credible ("the format your
  auditors already recognize").

## Preconditions

Neither pitch is credible before:

1. an installable `proofbound` + `proofbound-verify` release (F1/F2 of
   [first-hour-experience](first-hour-experience.md)); and
2. one public, third-party-verifiable artifact — the base64 or semver
   claim board with its receipt and a one-line verifier invocation —
   published where the reproducible-builds community lives.

## Actions and dates

1. Ship F1–F5 of [first-hour-experience](first-hour-experience.md)
   (~one focused week).
2. Publish the first public receipt + claim board (product analysis
   §8, item 3).
3. Submit to FOSDEM — reproducible-builds or Rust devroom, title
   "Make your software's claims compile," format: live on-stage
   receipt verification. **CFP window: devroom calls typically close
   late November–early December for early-February FOSDEM.** Working
   backward, preconditions 1–2 should exist by mid-November.
4. Submit the local-first framing to Local-First Conf when its CFP
   opens.
5. Draft the rebuilder-attestation adapter as a working note or spec
   candidate only after 1–3; it is the natural second conversation
   with the FOSDEM audience, not the first.

## Promotion criteria

Fold this note into the product vision's Phase 4 (as an explicit
distribution-vs-revenue wedge split) when both of the following hold:
a public receipt exists that a stranger has actually verified, and at
least one of the two talks is accepted. Until then this remains an
observation-backed hypothesis, and the note stays `exploring`.
