import Proofbound.Attribute
import ProofboundDemo.Transfer

namespace ProofboundDemo.Claims.Transfer

@[proofbound_claim "DEMO-TRANSFER-001"]
theorem accept_conserves
    {request : ProofboundDemo.Transfer.Request}
    {result : ProofboundDemo.Transfer.Decision}
    (hDecision : ProofboundDemo.Transfer.decide request = result)
    (hAccepted : result.code = .accepted) :
    result.fromBalance + result.toBalance =
      request.fromBalance + request.toBalance :=
  ProofboundDemo.Transfer.accept_conserves hDecision hAccepted

@[proofbound_claim "DEMO-TRANSFER-002"]
theorem accept_never_overdraws
    {request : ProofboundDemo.Transfer.Request}
    {result : ProofboundDemo.Transfer.Decision}
    (hDecision : ProofboundDemo.Transfer.decide request = result)
    (hAccepted : result.code = .accepted) :
    request.amount ≤ request.fromBalance ∧
      result.fromBalance = request.fromBalance - request.amount :=
  ProofboundDemo.Transfer.accept_never_overdraws hDecision hAccepted

@[proofbound_claim "DEMO-TRANSFER-003"]
theorem accept_respects_cap
    {request : ProofboundDemo.Transfer.Request}
    {result : ProofboundDemo.Transfer.Decision}
    (hDecision : ProofboundDemo.Transfer.decide request = result)
    (hAccepted : result.code = .accepted) :
    request.amount ≤ request.cap :=
  ProofboundDemo.Transfer.accept_respects_cap hDecision hAccepted

@[proofbound_claim "DEMO-TRANSFER-004"]
theorem denial_unchanged
    {request : ProofboundDemo.Transfer.Request}
    {result : ProofboundDemo.Transfer.Decision}
    (hDecision : ProofboundDemo.Transfer.decide request = result)
    (hDenied : result.code ≠ .accepted) :
    result.fromBalance = request.fromBalance ∧
      result.toBalance = request.toBalance :=
  ProofboundDemo.Transfer.denial_unchanged hDecision hDenied

end ProofboundDemo.Claims.Transfer
