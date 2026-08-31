# Proofbound: the assurance layer software has been missing

> Software should not merely build. Its claims should compile.

Proofbound can become the system that changes how serious software answers its
most important question:

> What, exactly, do we know about this release—and can someone else verify that
> answer without trusting us?

Today, that answer is scattered across tests, theorem prover output, model
checker logs, CI jobs, audit documents, issue trackers, source comments, and the
memories of a few senior engineers. A green build compresses all of that into a
colour while quietly losing the distinctions that matter. A test is not a
proof. A proof of a model is not automatically connected to the shipped code.
A successful checker process does not prove that it checked the intended
subject. A signed build attestation says who produced an artifact, not what the
artifact is known to do.

Proofbound turns that fragmented evidence into a precise, reviewable, portable
assurance product. It registers the claims a system makes, binds each claim to
the exact subject and evidence that supports it, preserves assumptions and
exclusions, applies release policy, and emits a receipt that an independent
verifier can check.

That is not another test runner. It is a new layer in the software supply
chain: the layer that carries meaning.

## The category: an assurance compiler

The simplest description of Proofbound is **an assurance compiler and release
gate**.

Source compilers answer whether source code can become an executable.
Proofbound answers whether the claims made about that executable are supported
by the registered evidence.

It compiles:

- claims about behaviour, safety, compatibility, and artifacts;
- ordinary tests, property tests, mutation witnesses, bounded model checks,
  source refinements, formal theorems, trusted transcriptions, independent
  checks, and human review;
- the exact code, data, tools, commands, environments, and trust assumptions
  behind that evidence;
- explicit policy describing what is sufficient for a particular release;

into:

- a claim board that says what is proved, tested, bounded, transcribed,
  artifact-bound, assumed, invalid, or still open;
- a fail-closed release decision;
- a content-addressed evidence history;
- and a portable receipt that can be verified away from the producing
  repository.

The result is a better primitive than a generic pass/fail badge. It lets the
product say, without hand-waving, `PROVED · ARTIFACT_BOUND · NONE`, or just as
importantly, `TESTED · MODEL_ONLY · ASSUMED` with a visible account of what
remains outside the claim.

## What changes when claims compile

The existing software-assurance stack provides useful fragments:

| Existing system | What it answers | What it usually cannot answer |
| --- | --- | --- |
| CI | Did these jobs report success? | What proposition did they establish? |
| Tests | Did selected examples behave as expected? | Was the relevant space exhausted or proved? |
| Formal tools | Did this model or theorem check? | Is it bound to the released bytes and current source? |
| SBOMs | What components are present? | What behavioural claims are supported? |
| Build provenance | Who built what, where, and how? | What the result is known to guarantee? |
| GRC evidence | Was a control documented? | Is the evidence current, reproducible, and mechanically connected? |
| Proofbound | What is established about this release, by which evidence, under which assumptions? | It deliberately reports the remaining open obligations instead of concealing them. |

Proofbound does not replace those systems. It gives them semantics and connects
them into a trustworthy whole.

### For developers

Assurance becomes an ordinary development loop rather than a late audit event.
A developer changes code, sees exactly which claims and evidence closures are
affected, and knows whether the change weakens a guarantee before review. They
can begin with tests and promote one valuable claim at a time to bounded or
formal evidence. Formal methods stop being an all-or-nothing programme.

### For security and formal-methods teams

Proof work becomes reusable product infrastructure. A theorem is no longer a
beautiful but isolated fact in a specialist repository; its audited statement,
axioms, source boundary, artifact linkage, and trust base become part of the
release contract. The product preserves the difference between proving a model,
refining source to that model, and binding the result to exact bytes.

### For release engineering

The release gate stops asking only whether all jobs are green. It can ask
whether every critical claim has the required evidence grade, whether all
evidence was produced from the reviewed tree, whether tool and harness
inventories match registration exactly, and whether any new assumption or
out-of-scope clause appeared.

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
proofbound check  ──► precise local failures and assurance diffs
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
rather than a source of disconnected green lights.

### 2. It creates progressive assurance

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

### 3. It makes negative space visible

Every serious assurance failure contains a sentence that was never written:
the test did not cover this case; the proof assumed this axiom; the model did
not include this dependency; the verifier rebuilt from private state; the
artifact was not actually tied to the theorem.

Proofbound treats “not proved / out of scope” as part of the product, not as
fine print. That could materially improve engineering decisions because the
absence of evidence becomes reviewable data.

### 4. It turns assurance into a portable supply-chain object

An independently verifiable receipt allows assurance to travel with a release.
Vendors can provide it to customers. Open-source maintainers can publish it.
Regulated teams can retain it. A downstream project can require a policy over
upstream claims rather than trusting a badge on a web page.

Over time this can create a **claim supply chain**: dependencies do not merely
declare versions and hashes; they carry machine-verifiable statements about
what has been established and where the assurance boundary ends.

### 5. It rewards honesty instead of confidence theatre

Proofbound has no need for a universal assurance score. A single number would
erase the distinctions that give the product value. The competitive advantage
is precision: a bounded check stays bounded, a model-only proof stays
model-only, an assumption stays visible, and unavailable evidence blocks the
promotion it was meant to support.

This makes the product unusually credible. It is built to prevent users—and
its own implementation—from stretching a pass.

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

## The path from excellent engine to exceptional product

### Phase 1: finish the trust kernel

Complete the eight hardening items, keep each security boundary independently
tested, and make the standalone verifier the final authority over every shipped
release fixture.

Exit condition: adversarial tests demonstrate that empty inventories, stale
caches, checker-authored linkage, receipt ambiguity, mismatched artifacts,
unregistered mutations, and unavailable tools cannot manufacture a stronger
status.

### Phase 2: perfect the first-hour experience

Make `proofbound init` produce a genuinely useful board for an ordinary existing
repository. Guide the user through three actions:

1. replace the example claim with one real product promise;
2. bind one test the project already runs;
3. record the most important assumption and exclusion.

The generated configuration should be small, commented, and valid. Error
messages should identify the claim, the broken boundary, and the next action.
`doctor` should distinguish unavailable, misconfigured, incompatible, and
ready tools.

Target outcome: a new team reaches an honest first claim board in fifteen
minutes and a portable verified receipt in under an hour, without installing a
formal toolchain.

### Phase 3: make pull requests assurance-aware

Build first-class GitHub and GitLab experiences around an **assurance diff**:

- claims added, removed, strengthened, or weakened;
- evidence that became stale or invalid;
- assumptions and exclusions that changed;
- trust-base additions;
- policy consequences for the release.

The review surface should lead with meaning, not manifest syntax. A reviewer
should be able to answer “what guarantee changed?” before opening a raw log.

Target outcome: Proofbound becomes useful on every security-sensitive pull
request, not only during formal-verification work.

### Phase 4: win a narrow, painful market first

Start with teams for whom behavioural assurance and artifact identity are
already expensive problems:

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

Target outcome: several real projects publish receipts that an external party
actually verifies and uses in a release or procurement decision.

### Phase 5: make assurance consumable across organizations

Add organization policy packs, approval workflows, retention, air-gapped
operation, keyless signing and transparency-log integration, and stable APIs for
artifact registries and deployment systems. Keep the receipt independently
verifiable and the verifier small enough to audit.

Allow a consumer to express policy such as:

- authentication claims must be at least `BOUNDED_CHECKED` and carry no
  undeclared assumptions;
- canonical-format claims must be `ARTIFACT_BOUND`;
- any new TCB component requires named approval;
- receipts must come from reviewed source and an allowed toolchain identity.

Target outcome: assurance becomes an enforceable interface between producers
and consumers, not a producer-authored PDF.

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
2. Existing evidence becomes structured and portable.
3. Visible gaps direct the next engineering investment.
4. Stronger evidence improves release confidence and external trust.
5. Consumers begin requesting receipts from dependencies and vendors.
6. Tool providers add adapters because receipts become a distribution channel
   for credible evidence.
7. More interoperable evidence makes Proofbound useful to more projects.

The defensibility is not merely in integrations or a dashboard. It is in the
semantic model, the fail-closed trust boundaries, the growing adversarial
corpus, the accumulated policy knowledge, and the network of claims and
receipts that other organizations learn to consume.

## How success should be measured

Proofbound should measure whether it improves decisions, not how many green
badges it emits.

Leading product measures:

- time from installation to the first honest claim board;
- time from a repository change to a useful assurance diff;
- percentage of critical claims with explicit assumptions and exclusions;
- percentage of release receipts independently verified outside producer CI;
- number of stale or mismatched evidence paths caught before release;
- number of claims progressively promoted without weakening their scope;
- number of downstream decisions that consume a receipt;
- time saved assembling recurring audit and customer evidence.

Trust measures:

- zero known paths by which adapter-authored booleans or exit status alone can
  upgrade assurance;
- cross-implementation agreement between compiler and independent verifier;
- complete public accounting of compatibility breaks and revoked receipt
  semantics;
- adversarial regression coverage for every discovered trust-boundary failure.

## Non-negotiable product principles

To become revolutionary, Proofbound must refuse several tempting shortcuts:

- **No universal score.** Preserve the dimensions of assurance.
- **No proof theatre.** Never present tool execution as stronger evidence than
  it is.
- **No formal-methods tollbooth.** Tier 0 must remain useful with ordinary tests
  and explicit open obligations.
- **No producer-only verdict.** The portable independent verifier remains a
  first-class product.
- **No hidden regeneration.** Verification does not rewrite the subject to make
  evidence pass.
- **No erased uncertainty.** Assumptions and exclusions travel with the claim.
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
release engineering without being diluted into a badge.

If source control made changes reviewable, CI made builds repeatable, and SBOMs
made components visible, Proofbound can make **software claims accountable**.

That is the revolution: not pretending every program is proved, but making it
normal for every consequential release to say precisely what is established,
why anyone should believe it, and where belief must stop.
