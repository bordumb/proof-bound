import ProofboundArtifactDemo.Certificate
import Proofbound.Attribute

/-!
The two public demo claims use compiled `@[proofbound_claim "..."]`
attribution. Supporting theorems on this registered surface carry explicit
`proofbound_exempt` reasons.
-/

namespace ProofboundArtifactDemo.Claims

open ProofboundArtifactDemo.Certificate

attribute [proofbound_exempt "Compiler-generated equation theorem materialized while reducing the digest-binding helper."]
  ProofboundArtifactDemo.Certificate.acceptsDigest.eq_1

/-- Exact committed bytes of `fixtures/valid-basic.pbac`. -/
def publishedBytes : List UInt8 := [
  0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x07,
  0x01, 0x03, 0x04, 0x80, 0x01, 0x09, 0xfa, 0x06]

/-- Literal SHA-256 `dd7cf87b...561dfe2d`, independently reproducible from
the committed fixture. -/
def publishedDigest : ByteArray := ByteArray.mk #[
  0xdd, 0x7c, 0xf8, 0x7b, 0xa3, 0x53, 0x5a, 0xad,
  0x43, 0x1c, 0x47, 0x3b, 0x71, 0x28, 0x6f, 0xb6,
  0x80, 0x6f, 0xcc, 0x78, 0x5f, 0xc3, 0xb3, 0x92,
  0x90, 0xc4, 0xa9, 0x9d, 0x56, 0x1d, 0xfe, 0x2d]

set_option maxRecDepth 100000 in
/-! The small parser/checker reduces in the kernel. -/
@[proofbound_exempt "Kernel-reduced certificate-specific premise used by the artifact binding theorem."]
theorem publishedAccepts : checkList publishedBytes = true := by
  decide

/-- SHA-256 evaluation is deliberately and visibly native. This is the only
native premise in the artifact binding; the claim theorem below does not depend
on it. -/
@[proofbound_exempt "Native SHA-256 premise; exposed through the registered artifact-soundness evidence unit."]
theorem publishedDigestIsSha256 :
    Sha256.hash (ByteArray.mk publishedBytes.toArray) = publishedDigest := by
  native_decide

/-- Exact-byte acceptance conjoined with the literal SHA-256 digest. The native
evaluation mode is recorded in both evidence manifests. -/
@[proofbound_exempt "Boolean helper consumed by the registered artifact-soundness theorem."]
theorem publishedAcceptsDigest :
    acceptsDigest publishedBytes publishedDigest = true := by
  simp [acceptsDigest, publishedAccepts, publishedDigestIsSha256]

/-- The certificate-specific artifact-soundness result: exact canonical bytes
have the registered meaning and the published digest is their SHA-256. -/
@[proofbound_exempt "Binding theorem registered as evidence for PBAC-SUM-001; the public claim theorem is publishedTotal."]
theorem publishedArtifactSoundness :
    MeaningList publishedBytes ∧
      Sha256.hash (ByteArray.mk publishedBytes.toArray) = publishedDigest :=
  acceptsDigest_sound publishedAcceptsDigest

/-- Axiom-free artifact-bound public claim. -/
@[proofbound_claim "PBAC-SUM-001"]
theorem publishedTotal : MeaningList publishedBytes :=
  checkList_sound publishedAccepts

/-- An intentionally abstract proposition representing facts outside the
certificate's arithmetic model. It has no constructors. -/
inductive ProviderMeasurementsAccurate : Prop

/-- Explicit external premise. The certificate establishes arithmetic only;
it cannot establish the accuracy of a physical measurement provider. -/
axiom providerMeasurementsAccurate : ProviderMeasurementsAccurate

def CalibratedMeaning (bytes : List UInt8) : Prop :=
  MeaningList bytes ∧ ProviderMeasurementsAccurate

/-- Artifact-bound claim whose residual external premise is intentionally
visible in the assumption manifest and Lean axiom audit. -/
@[proofbound_claim "PBAC-CALIBRATED-001"]
theorem publishedCalibratedTotal : CalibratedMeaning publishedBytes :=
  ⟨publishedTotal, providerMeasurementsAccurate⟩

/-- Digest-bound version of the explicitly axiomatized claim. -/
@[proofbound_exempt "Binding theorem registered as evidence for PBAC-CALIBRATED-001; the public claim theorem is publishedCalibratedTotal."]
theorem publishedCalibratedArtifactSoundness :
    CalibratedMeaning publishedBytes ∧
      Sha256.hash (ByteArray.mk publishedBytes.toArray) = publishedDigest :=
  ⟨publishedCalibratedTotal, publishedDigestIsSha256⟩

end ProofboundArtifactDemo.Claims
