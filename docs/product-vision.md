# Proofbound: the control plane for software uncertainty

> Software should not merely build. Its claims should compile.

Modern engineering organizations do not suffer from a lack of signals. They
have SLA monitors, code-quality platforms, security scanners, dependency bots,
test suites, theorem provers, model checkers, audit controls, and incident
systems. Each tool can identify something locally interesting. Almost none can
say whether that signal changes a promise the product makes.

The result is notification fatigue. Engineers are repeatedly interrupted by
findings that lack product context, while the assumptions and uncertainties
that genuinely matter remain scattered across source comments, exceptions,
dashboards, tickets, and institutional memory. Muting the alert makes the noise
disappear; it does not make the uncertainty governed.

Proofbound can change that. It can become the system through which serious
software answers two connected questions:

> What, exactly, do we know about this release—and can someone else verify that
> answer without trusting us?

> What are we assuming, where are we uncertain, and which changes are important
> enough to require a human being's attention?

Today, the answer is scattered across tool output and the memories of a few
senior engineers. A green build compresses all of that into a colour while
quietly losing the distinctions that matter. A test is not a proof. A proof of
a model is not automatically connected to the shipped code. A successful
checker process does not prove that it checked the intended subject. A signed
build attestation says who produced an artifact, not what the artifact is known
to do. A thousand warnings do not reveal which guarantee is in danger.

Proofbound turns that fragmented evidence and uncertainty into a precise,
reviewable, portable assurance product. It registers the claims a system makes,
binds each claim to the exact subject and evidence that supports it, preserves
assumptions and exclusions as durable objects, applies release policy, and
emits a receipt that an independent verifier can check. Tools become sensors;
the claim graph supplies the meaning; notifications become consequences of a
material assurance change rather than another raw feed.

That is not another test runner or alerting platform. It is a new layer in the
software supply chain: the layer that carries meaning, uncertainty, and the
reason a person should care.

## The category: an assurance compiler and uncertainty control plane

The simplest description of Proofbound is **an assurance compiler, uncertainty
control plane, and release gate**.

Source compilers answer whether source code can become an executable.
Proofbound answers whether the claims made about that executable are supported
by the registered evidence. As a control plane, it also maintains the known
assumptions, exclusions, and open obligations around those claims, then decides
which changes are material enough to surface.

It compiles:

- claims about behaviour, safety, compatibility, and artifacts;
- ordinary tests, property tests, mutation witnesses, bounded model checks,
  source refinements, formal theorems, trusted transcriptions, independent
  checks, and human review;
- the exact code, data, tools, commands, environments, and trust assumptions
  behind that evidence;
- explicit uncertainty: assumptions, exclusions, unsupported boundaries, open
  obligations, ownership, rationale, and review policy;
- explicit policy describing what is sufficient for a particular release;

into:

- a claim board that says what is proved, tested, bounded, transcribed,
  artifact-bound, assumed, invalid, or still open;
- an uncertainty ledger that keeps accepted risk visible without repeatedly
  paging engineers about unchanged state;
- an assurance diff that identifies meaningful changes to claims, evidence,
  assumptions, exclusions, and trust boundaries;
- a fail-closed release decision;
- a content-addressed evidence history;
- and a portable receipt that can be verified away from the producing
  repository.

The result is a better primitive than a generic pass/fail badge. It lets the
product say, without hand-waving, `PROVED · ARTIFACT_BOUND · NONE`, or just as
importantly, `TESTED · MODEL_ONLY · ASSUMED` with a visible account of what
remains outside the claim. It also lets the product remain quiet when none of
those material facts changed.

## What changes when claims compile

The existing software-assurance stack provides useful fragments:

| Existing system | What it answers | What it usually cannot answer |
| --- | --- | --- |
| CI | Did these jobs report success? | What proposition did they establish? |
| Code-quality and security scanners | Did a detector match something? | Does this finding weaken a material product claim? |
| SLA and observability systems | Is production outside an operational threshold? | Which engineering assumption or guarantee changed? |
| Tests | Did selected examples behave as expected? | Was the relevant space exhausted or proved? |
| Formal tools | Did this model or theorem check? | Is it bound to the released bytes and current source? |
| SBOMs | What components are present? | What behavioural claims are supported? |
| Build provenance | Who built what, where, and how? | What the result is known to guarantee? |
| GRC evidence | Was a control documented? | Is the evidence current, reproducible, and mechanically connected? |
| Proofbound | What is established, what remains uncertain, and what materially changed? | It deliberately reports open obligations and cannot promise discovery of unknowable unknowns. |

Proofbound does not replace those systems. It gives their signals semantics,
connects them into a trustworthy whole, and provides the context needed to
decide whether a human should be interrupted.

### For developers

Assurance becomes an ordinary development loop rather than a late audit event.
A developer changes code, sees exactly which claims and evidence closures are
affected, and knows whether the change weakens a guarantee before review. They
can begin with tests and promote one valuable claim at a time to bounded or
formal evidence. Formal methods stop being an all-or-nothing programme. An
unchanged accepted assumption remains visible in the ledger without generating
the same warning every day; a newly introduced or expired assumption reaches
the responsible engineer with the affected claim and a concrete reason to act.

### For security and formal-methods teams

Proof work becomes reusable product infrastructure. A theorem is no longer a
beautiful but isolated fact in a specialist repository; its audited statement,
axioms, source boundary, artifact linkage, and trust base become part of the
release contract. The product preserves the difference between proving a model,
refining source to that model, and binding the result to exact bytes. Existing
scanners and formal tools become evidence producers, not independent sources of
unprioritized alerts.

### For release engineering

The release gate stops asking only whether all jobs are green. It can ask
whether every critical claim has the required evidence grade, whether all
evidence was produced from the reviewed tree, whether tool and harness
inventories match registration exactly, and whether any new assumption or
out-of-scope clause appeared. Release policy can react to assurance transitions
rather than to the volume of findings produced by a tool.

### For auditors, customers, and regulators

Evidence collection changes from archaeology to verification. Instead of
screenshots and exported CI logs, a recipient receives a bounded, canonical
release package and verifies it with a small independent tool. They can see the
claim, the evidence type, the subject identity, the trust base, the assumptions,
and the exclusions without receiving the producer's private repository.

### For leadership

Risk becomes legible without becoming a fake aggregate score. Leaders can see
which product promises are strongly established, which rest on assumptions,
which have only empirical support, and which remain open. Investment can follow
the most consequential assurance gaps instead of the loudest tool output.
Notification volume, accepted risk, and unowned uncertainty become separate,
measurable concerns rather than one undifferentiated backlog.

## The product experience

The eventual experience should feel almost obvious:

```text
proofbound init
      │
      ▼
Register the promises the software already makes
      │
      ▼
Bind existing tests and checks; expose assumptions and open obligations
      │
      ▼
Build the uncertainty ledger: scope, owner, rationale, review policy
      │
      ▼
proofbound check  ──► precise failures + material assurance diff
      │
      ▼
Promote selected claims with bounded checks, proofs, refinement, or binding
      │
      ▼
proofbound release ──► canonical release + portable assurance receipt
      │
      ▼
proofbound-verify ──► independent, repository-free verdict
```

The first useful result must not require Lean, Kani, Charon, or Aeneas. A team
should obtain value by registering claims, connecting the tests it already
runs, and making assumptions explicit. Advanced evidence should be an
incremental promotion path, not an adoption toll.

Notifications should be a derived view of this state, never the source of
truth. A stable known risk belongs on the claim board. A human interruption is
reserved for a transition: a claim weakened, evidence became stale, an
assumption was introduced or expired, an exclusion broadened, the trusted
computing base grew, or release policy was crossed.

The common case should be reassuringly quiet:

> No material assurance change.

When action is necessary, the message should carry enough meaning to act:

> `AUTH-004` changed from `BOUNDED_CHECKED` to `INVALID`: the modified
> authorization branch is outside the registered harness inventory.
>
> `TOKEN-009` gained a clock-skew assumption. It has no owner or review date.

This is the opposite of suppression. The uncertainty is retained, attributed,
and reviewable even when it does not justify another notification.

The magical moment is not “we installed a formal tool.” It is this:

> A pull request changed a security-relevant claim, Proofbound showed exactly
> which guarantee weakened and why, the author supplied stronger evidence, and
> the resulting release receipt was independently verified by the consumer.

## Why this can revolutionise software assurance

### 1. It makes the unit of assurance a claim, not a job

The industry organises assurance around tools and pipelines because those are
easy to execute. The user actually cares about claims: authorization cannot be
bypassed, canonical bytes are rejected when malformed, an update preserves an
invariant, a cryptographic artifact corresponds to an audited theorem.

Once claims are first-class, every tool becomes evidence for a proposition
rather than a source of disconnected green lights or notifications.

### 2. It replaces notification fatigue with obligation-aware engineering

Most engineering notifications are emitted at the wrong abstraction level. A
tool sees a local event and immediately asks for attention. It does not know
whether the event affects a material product promise, duplicates an accepted
risk, falls outside the shipping boundary, or has already been assigned to an
owner with a deliberate review date.

Proofbound can separate **assurance state** from **notification policy**. The
state remains complete and durable: claims, evidence, assumptions, exclusions,
open obligations, owners, and history. Notification is reserved for meaningful
state transitions:

- a claim is added, weakened, invalidated, or removed;
- evidence becomes stale, unavailable, or detached from its subject;
- an assumption enters a critical closure, changes, or passes its review date;
- an exclusion expands;
- a new component enters the trusted computing base;
- a release moves across a registered policy boundary.

“Mute this alert” can become a governed decision instead of information loss:

> Accept assumption `CLOCK-017` for the token-validation scope, owned by the
> Identity team, with this rationale, until this review date.

The assumption remains visible in every relevant claim and release receipt.
Engineers are not paged again merely because another tool rediscovered the same
unchanged fact. This is how Proofbound can reduce noise without concealing
risk: fewer interruptions, a stronger institutional memory, and much higher
signal when it does speak.

### 3. It creates progressive assurance

Most teams cannot formally verify an entire system, and they should not need to
pretend otherwise. Proofbound makes the ladder explicit:

- start with an open claim;
- bind an ordinary regression test;
- add mutation evidence showing that the test detects a specific fault;
- register a finite domain and model-check it;
- audit a theorem;
- refine the shipping implementation to the model;
- bind the theorem's content to the released artifact.

Each step creates honest value. None is silently promoted into the next.

### 4. It makes negative space visible

Every serious assurance failure contains a sentence that was never written:
the test did not cover this case; the proof assumed this axiom; the model did
not include this dependency; the verifier rebuilt from private state; the
artifact was not actually tied to the theorem.

Proofbound treats “not proved / out of scope” as part of the product, not as
fine print. That could materially improve engineering decisions because the
absence of evidence becomes reviewable data. When a gap is accepted, it becomes
a durable obligation rather than a warning that disappears into a suppression
list. When it changes, the affected claims identify who needs to care.

### 5. It turns assurance into a portable supply-chain object

An independently verifiable receipt allows assurance to travel with a release.
Vendors can provide it to customers. Open-source maintainers can publish it.
Regulated teams can retain it. A downstream project can require a policy over
upstream claims rather than trusting a badge on a web page.

Over time this can create a **claim supply chain**: dependencies do not merely
declare versions and hashes; they carry machine-verifiable statements about
what has been established and where the assurance boundary ends.

### 6. It rewards honesty instead of confidence theatre

Proofbound has no need for a universal assurance score. A single number would
erase the distinctions that give the product value. The competitive advantage
is precision: a bounded check stays bounded, a model-only proof stays
model-only, an assumption stays visible, and unavailable evidence blocks the
promotion it was meant to support.

This makes the product unusually credible. It is built to prevent users—and
its own implementation—from stretching a pass. It also refuses the stronger
but impossible promise of enumerating every unknown unknown. Proofbound can
make registered and discovered uncertainty durable and difficult to erase; it
cannot claim that undiscovered uncertainty does not exist.

## The foundation that makes the promise believable

The current hardening programme is product work, not invisible plumbing. Each
part protects a promise a user will eventually rely upon:

1. **Theorem-derived artifact binding** ensures an artifact-bound status comes
   from the audited theorem content, not from a checker claiming that it did the
   binding.
2. **Complete receipts** preserve model assumptions, unknown measurements,
   internal and public claim language, and the full executed command sequence.
3. **Authoritative translation manifests** make generated source refinement
   deterministic, exact, cache-safe, and update-safe.
4. **Executable trusted transcription** turns a specification-only evidence
   category into a real round-trip route with explicit transcriber and
   re-encoder trust identities.
5. **Exact adapter inventories** prevent a tool from succeeding after checking
   nothing, checking the wrong targets, or merely exiting zero.
6. **Per-mutation evidence** will isolate each mutation witness to the claim it
   protects and make replay a sealed, reproducible operation.
7. **Tool-specific capability diagnosis** will tell users what is actually
   installed and runnable instead of producing generic or misleading health
   signals.
8. **Pre-registration quality guidance** will require experiment questions and
   pass criteria to be internally consistent and mathematically precise before
   results can influence them.

Together these changes make the system worthy of sitting on a release boundary.
They also make claim-aware notification credible. If an adapter can report an
empty success, a cache can silently reuse stale evidence, or a checker can
invent artifact linkage, then the assurance state is too noisy to drive human
attention. Exact, independently checked state is the prerequisite for being
quiet with confidence.

## The path from excellent engine to exceptional product

### Phase 1: finish the trust kernel

Complete the eight hardening items, keep each security boundary independently
tested, and make the standalone verifier the final authority over every shipped
release fixture.

Exit condition: adversarial tests demonstrate that empty inventories, stale
caches, checker-authored linkage, receipt ambiguity, mismatched artifacts,
unregistered mutations, and unavailable tools cannot manufacture a stronger
status. Every notification-relevant transition must be derived from that same
validated state rather than from an adapter-authored severity label.

### Phase 2: perfect the first-hour experience

Make `proofbound init` produce a genuinely useful board for an ordinary existing
repository. Guide the user through three actions:

1. replace the example claim with one real product promise;
2. bind one test the project already runs;
3. record the most important assumption and exclusion, including their scope,
   rationale, owner, and review policy.

The generated configuration should be small, commented, and valid. Error
messages should identify the claim, the broken boundary, and the next action.
`doctor` should distinguish unavailable, misconfigured, incompatible, and
ready tools. The initial board should distinguish unowned uncertainty from
accepted, governed uncertainty rather than treating both as another alert.

Target outcome: a new team reaches an honest first claim board in fifteen
minutes and a portable verified receipt in under an hour, without installing a
formal toolchain.

### Phase 3: make pull requests and notifications claim-aware

Build first-class GitHub and GitLab experiences around an **assurance diff**:

- claims added, removed, strengthened, or weakened;
- evidence that became stale or invalid;
- assumptions and exclusions that changed;
- assumptions that became unowned or passed their review date;
- trust-base additions;
- policy consequences for the release.

The review surface should lead with meaning, not manifest syntax. A reviewer
should be able to answer “what guarantee changed?” before opening a raw log.

Integrate existing code-quality, security, test, SLA, and incident signals as
inputs to the claim graph. Do not forward their feeds unchanged. Route a
notification only when the normalized signal changes a material claim or
registered obligation. Deduplicate repeated observations into one durable
state object; let ownership and policy determine the destination and urgency.

The product should make three outcomes visually and operationally distinct:

- **quiet:** the signal changes no registered material assurance state;
- **visible, not interrupting:** a known or accepted obligation remains
  unchanged on the board;
- **action required:** a material transition occurred and the responsible
  owner receives the affected claim, evidence, and next decision.

Target outcome: Proofbound becomes useful on every security-sensitive pull
request, not only during formal-verification work, while reducing the number of
low-context notifications engineers must process.

### Phase 4: win a narrow, painful market first

(An exploratory companion, [notes/distribution-wedge.md](notes/distribution-wedge.md),
records firsthand FOSDEM and Local-First demand signals and proposes an
adoption wedge distinct from this paying wedge.)

Start with teams for whom behavioural assurance and artifact identity are
already expensive problems—and where overlapping tools already create costly
notification fatigue:

- security-critical Rust libraries;
- cryptographic and canonical-serialization implementations;
- authorization, identity, and policy engines;
- consensus and protocol code;
- safety-critical components with existing formal or model-checking investment;
- vendors repeatedly asked to substantiate the same security claims for
  customers and auditors.

Package opinionated profiles and reference projects around these cases. The
sales message is not “adopt formal methods.” It is:

> Stop rebuilding the truth about every release from CI logs and audit prose.

And it is:

> Stop asking engineers to triage every tool finding before anyone knows which
> product promise it affects.

Target outcome: several real projects publish receipts that an external party
actually verifies and uses in a release or procurement decision.

### Phase 5: make assurance consumable across organizations

Add organization policy packs, approval workflows, retention, air-gapped
operation, keyless signing and transparency-log integration, and stable APIs for
artifact registries and deployment systems. Keep the receipt independently
verifiable and the verifier small enough to audit. Add organizational routing
policy for ownership, review dates, escalation, and accepted assumptions while
keeping the underlying uncertainty visible in the receipt.

Allow a consumer to express policy such as:

- authentication claims must be at least `BOUNDED_CHECKED` and carry no
  undeclared assumptions;
- canonical-format claims must be `ARTIFACT_BOUND`;
- any new TCB component requires named approval;
- accepted assumptions must carry an owner and an unexpired review date;
- receipts must come from reviewed source and an allowed toolchain identity.

Target outcome: assurance becomes an enforceable interface between producers
and consumers, not a producer-authored PDF, while notification policy becomes a
controlled projection of the same verified assurance state.

### Phase 6: open the ecosystem without weakening the boundary

Publish stable schemas, adapter conformance kits, an adversarial cross-check
corpus, and a clear compatibility policy. Make it straightforward to add a new
evidence producer while making it difficult to exaggerate what that producer
establishes.

Invite formal-tool authors, security vendors, auditors, and research teams to
emit Proofbound-compatible evidence. Keep status derivation and portable
verification independent of adapter claims.

Target outcome: tools compete on the evidence they can rigorously contribute,
while Proofbound remains the neutral compiler of the final assurance statement.

### Phase 7: earn category authority

Commission external security review of the trust kernel and independent
verifier. Publish red-team cases, failed experiments, compatibility breaks, and
the exact limits of every assurance grade. Create a public benchmark of
realistic claims and seeded faults across tests, model checkers, theorem
provers, translation pipelines, and artifact checkers.

Target outcome: teams trust Proofbound not because it promises certainty, but
because it is exceptionally disciplined about showing where certainty ends.

## The product flywheel

If executed well, Proofbound has a powerful compounding loop:

1. A project registers valuable claims.
2. Existing evidence and known uncertainty become structured and portable.
3. Tool signals acquire claim context; unchanged obligations stop creating
   repeated interruptions.
4. Visible gaps direct the next engineering investment.
5. Stronger evidence improves release confidence and external trust.
6. Consumers begin requesting receipts from dependencies and vendors.
7. Tool providers add adapters because receipts become a distribution channel
   for credible evidence.
8. More interoperable evidence makes Proofbound useful to more projects.

The defensibility is not merely in integrations or a dashboard. It is in the
semantic model, the fail-closed trust boundaries, the growing adversarial
corpus, the accumulated policy knowledge, the durable organizational memory of
assumptions and obligations, and the network of claims and receipts that other
organizations learn to consume.

## How success should be measured

Proofbound should measure whether it improves decisions, not how many green
badges it emits.

Leading product measures:

- time from installation to the first honest claim board;
- time from a repository change to a useful assurance diff;
- percentage of critical claims with explicit assumptions and exclusions;
- percentage of assumptions and open obligations with an owner, rationale,
  scope, and current review policy;
- reduction in repeated tool notifications that correspond to no material
  assurance change;
- percentage of interrupting notifications tied to a claim transition or
  policy boundary;
- median time to understand and route a material assurance regression;
- percentage of release receipts independently verified outside producer CI;
- number of stale or mismatched evidence paths caught before release;
- number of claims progressively promoted without weakening their scope;
- number of downstream decisions that consume a receipt;
- time saved assembling recurring audit and customer evidence.

Trust measures:

- zero known paths by which adapter-authored booleans or exit status alone can
  upgrade assurance;
- zero paths by which muting a notification deletes its underlying assumption
  or obligation;
- cross-implementation agreement between compiler and independent verifier;
- complete public accounting of compatibility breaks and revoked receipt
  semantics;
- adversarial regression coverage for every discovered trust-boundary failure.

## Non-negotiable product principles

To become revolutionary, Proofbound must refuse several tempting shortcuts:

- **No universal score.** Preserve the dimensions of assurance.
- **No raw-tool paging.** A detector output becomes a human interruption only
  through claim context and explicit policy.
- **No proof theatre.** Never present tool execution as stronger evidence than
  it is.
- **No formal-methods tollbooth.** Tier 0 must remain useful with ordinary tests
  and explicit open obligations.
- **No producer-only verdict.** The portable independent verifier remains a
  first-class product.
- **No hidden regeneration.** Verification does not rewrite the subject to make
  evidence pass.
- **No erased uncertainty.** Assumptions and exclusions travel with the claim.
- **No disappearing suppression.** Accepting a risk changes its owner and
  review policy; it does not delete it from organizational memory.
- **No completeness fiction.** Enumerate registered and discovered uncertainty
  precisely without claiming that unknown unknowns have been eliminated.
- **No private-repository leakage.** Receipts carry sufficient identities and
  results without requiring disclosure of producer internals.
- **No compatibility fiction.** Security-relevant wire changes are versioned,
  migrated, and documented honestly.

## The destination

The long-term opportunity is bigger than better CI and more approachable formal
verification.

Proofbound can make software guarantees into durable, inspectable supply-chain
objects. It can let a maintainer publish not only an artifact, but an exact
account of what is known about it. It can let a customer verify that account
without inheriting the producer's entire environment. It can let a developer
see the assurance consequence of a code change while the change is still small.
It can let formal evidence escape specialist silos and participate in ordinary
release engineering without being diluted into a badge. And it can give an
organization a shared memory of where its software makes assumptions, where it
is uncertain, which uncertainty has been deliberately accepted, and which
change genuinely deserves attention.

If source control made changes reviewable, CI made builds repeatable, and SBOMs
made components visible, Proofbound can make **software claims accountable**.

That is the revolution: not pretending every program is proved, but making it
normal for every consequential release to say precisely what is established,
why anyone should believe it, and where belief must stop. The engineering
organization becomes quieter not because problems are hidden, but because
uncertainty is finally enumerated, governed, and connected to the promises that
matter.
