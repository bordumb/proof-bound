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
