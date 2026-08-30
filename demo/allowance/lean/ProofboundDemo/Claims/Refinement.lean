import Proofbound.Attribute
import ProofboundDemo.TransferRefinement

namespace ProofboundDemo.Claims.Refinement

@[proofbound_claim "DEMO-TRANSFER-005"]
theorem decideTransfer_refines
    (request : ProofboundDemo.KernelBridge.Request)
    (representation : request.Valid) :
    ProofboundDemo.KernelBridge.decideTransfer request =
      ProofboundDemo.Transfer.decide request.toModel :=
  ProofboundDemo.TransferRefinement.decideTransfer_refines request representation

end ProofboundDemo.Claims.Refinement
