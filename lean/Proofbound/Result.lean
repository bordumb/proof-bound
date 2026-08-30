/-! Canonical small result types shared by Proofbound Lean consumers. -/

namespace Proofbound

inductive EvidenceOutcome where
  | passed
  | failed
  | drifted
  | skipped
  deriving BEq, DecidableEq, Repr

structure CheckResult where
  accepted : Bool
  code : String
  consumed : Nat
  deriving BEq, DecidableEq, Repr

end Proofbound

