import Proofbound.Result
import Proofbound.Sha256

/-! Generic, domain-neutral artifact and digest theorem combinators. -/

namespace Proofbound.Artifact

def DigestBound (bytes : ByteArray) (expectedHex : String) : Prop :=
  Proofbound.sha256Hex bytes = expectedHex

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

