import ProofboundDemo.Bridges.Kernel

namespace ProofboundDemo.TransferRefinement

theorem decideTransfer_refines
    (request : ProofboundDemo.KernelBridge.Request)
    (_representation : request.Valid) :
    ProofboundDemo.KernelBridge.decideTransfer request =
      ProofboundDemo.Transfer.decide request.toModel := by
  rfl

end ProofboundDemo.TransferRefinement
