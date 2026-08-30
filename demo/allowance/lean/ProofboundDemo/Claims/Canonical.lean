import Proofbound.Attribute
import ProofboundDemo.Canonical

namespace ProofboundDemo.Claims.Canonical

@[proofbound_claim "DEMO-TRANSFER-006"]
theorem acceptedFixture_decodes :
    ProofboundDemo.Canonical.decode ProofboundDemo.Canonical.acceptedFixture =
      some ProofboundDemo.Canonical.acceptedRequest :=
  ProofboundDemo.Canonical.acceptedFixture_decodes

end ProofboundDemo.Claims.Canonical
