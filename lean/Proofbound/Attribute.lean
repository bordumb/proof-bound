import Lean

/-!
# Public claim attributes

The attributes carry identity only. They do not assert proof status. Audit
tooling reads their persistent compiled-environment extensions.
-/

open Lean

namespace Proofbound

syntax (name := proofbound_claim) "proofbound_claim" ppSpace str : attr
syntax (name := proofbound_exempt) "proofbound_exempt" ppSpace str : attr

/-- Stable Proofbound claim ID attached to a public theorem declaration. -/
initialize proofboundClaimAttr : ParametricAttribute String ←
  registerParametricAttribute {
    name := `proofbound_claim
    descr := "stable Proofbound public claim ID"
    getParam := fun _ stx => withRef stx do
      match stx with
      | `(attr| proofbound_claim $id:str) =>
          let value := id.getString
          if value.isEmpty then throwError "Proofbound claim ID may not be empty"
          pure value
      | _ => Elab.throwUnsupportedSyntax
  }

/-- Reviewed reason why a theorem on a public surface is not a public claim. -/
initialize proofboundExemptAttr : ParametricAttribute String ←
  registerParametricAttribute {
    name := `proofbound_exempt
    descr := "recorded reason a theorem is not a public Proofbound claim"
    getParam := fun _ stx => withRef stx do
      match stx with
      | `(attr| proofbound_exempt $reason:str) =>
          let value := reason.getString
          if value.isEmpty then throwError "Proofbound exemption reason may not be empty"
          pure value
      | _ => Elab.throwUnsupportedSyntax
  }

def claimId? (env : Environment) (decl : Name) : Option String :=
  proofboundClaimAttr.getParam? env decl

def exemptionReason? (env : Environment) (decl : Name) : Option String :=
  proofboundExemptAttr.getParam? env decl

end Proofbound
