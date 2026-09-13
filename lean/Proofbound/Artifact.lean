import Proofbound.Result
import Proofbound.Sha256

/-! Generic, domain-neutral artifact and digest theorem combinators. -/

namespace Proofbound.Artifact

def DigestBound (bytes : ByteArray) (expectedHex : String) : Prop :=
  Proofbound.sha256Hex bytes = expectedHex

/--
The audited, versioned statement form for an artifact-bound public claim.

The first four arguments are deliberately explicit string literals.  The Lean
audit preserves the elaborated application in ExprWire, so independent
consumers can recover the exact claim, artifact schema, logical name, and
digest without trusting a checker-authored flag.  Adapters require
`expectedSha256` to use canonical `sha256:` plus 64 lowercase hexadecimal
digits.
-/
structure DigestBindingV1
    (claimId artifactSchema artifactLogicalName expectedSha256 : String)
    (bytes : ByteArray)
    (meaning : ByteArray → Prop) : Prop where
  digest : "sha256:" ++ Proofbound.sha256Hex bytes = expectedSha256
  meaning_holds : meaning bytes

/-- One reviewed member of a closed artifact-binding set. The logical name and
digest remain direct fields so independent statement-wire consumers can select
one exact release artifact without evaluating Lean definitions. -/
structure DigestBindingMemberV1 where
  artifactLogicalName : String
  expectedSha256 : String
  bytes : ByteArray

/--
The audited statement form for one semantic claim shipped as a closed set of
artifacts. Every member binds its own bytes to its literal digest and satisfies
the same semantic predicate. Release contexts may check one member, but cannot
add a member that is absent from this theorem.
-/
structure DigestBindingSetV1
    (claimId artifactSchema : String)
    (members : List DigestBindingMemberV1)
    (meaning : ByteArray → Prop) : Prop where
  digest : ∀ member ∈ members,
    "sha256:" ++ Proofbound.sha256Hex member.bytes = member.expectedSha256
  meaning_holds : ∀ member ∈ members, meaning member.bytes

theorem accepted_and_digest_implies_meaning
    (bytes : ByteArray)
    (expectedHex : String)
    (accepts : ByteArray → Bool)
    (meaning : ByteArray → Prop)
    (sound : ∀ candidate, accepts candidate = true → meaning candidate)
    (accepted : accepts bytes = true)
    (digest : DigestBound bytes expectedHex) :
    DigestBound bytes expectedHex ∧ meaning bytes :=
  ⟨digest, sound bytes accepted⟩

theorem no_digest_substitution
    (published candidate : ByteArray)
    (expectedHex : String)
    (publishedBound : DigestBound published expectedHex)
    (candidateBound : DigestBound candidate expectedHex)
    (hashInjectiveAtExpected :
      ∀ left right, DigestBound left expectedHex → DigestBound right expectedHex → left = right) :
    candidate = published :=
  hashInjectiveAtExpected candidate published candidateBound publishedBound

end Proofbound.Artifact
