import Lean
import Proofbound.Attribute
import Proofbound.ExprWire

/-!
# Compiled public-claim audit

The executable imports the requested modules, enumerates the persistent
`proofbound_claim` attribute from the compiled environment, serializes theorem
types without pretty-printing, and computes transitive axiom inventories.
-/

open Lean

namespace Proofbound.Audit

def declarationKind : ConstantInfo → String
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "definition"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quotient"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

def moduleNameFor (env : Environment) (declaration : Name) : Name :=
  match env.getModuleIdxFor? declaration with
  | some index => env.header.moduleNames[index.toNat]!
  | none => env.header.mainModule

structure Entry where
  claimId : String
  declaration : Name
  deriving Inhabited, Repr

def publicClaims (env : Environment) : Array Entry :=
  env.constants.fold (init := #[]) fun entries declaration _ =>
    match Proofbound.claimId? env declaration with
    | some claimId => entries.push { claimId, declaration }
    | none => entries

def validateUniqueIds (entries : Array Entry) : Except String Unit := do
  let sorted := entries.qsort fun left right => left.claimId < right.claimId
  for index in [1:sorted.size] do
    if sorted[index - 1]!.claimId == sorted[index]!.claimId then
      throw s!"duplicate proofbound_claim ID {sorted[index]!.claimId} on {sorted[index - 1]!.declaration} and {sorted[index]!.declaration}"

def validateSurfaces (env : Environment) (surfaces : Array Name) : Except String (Array Json) := do
  let mut exemptions := #[]
  for (declaration, info) in env.constants do
    if declarationKind info != "theorem" then continue
    let moduleName := moduleNameFor env declaration
    if !surfaces.contains moduleName then continue
    match Proofbound.claimId? env declaration, Proofbound.exemptionReason? env declaration with
    | some _, none => pure ()
    | none, some reason =>
        exemptions := exemptions.push <| Json.mkObj [
          ("declaration", declaration.toString),
          ("module", moduleName.toString),
          ("reason", reason)]
    | some _, some _ => throw s!"{declaration} cannot be both a public claim and exempt"
    | none, none => throw s!"unattributed theorem {declaration} on public claim surface {moduleName}"
  return exemptions

def auditEntry (entry : Entry) : MetaM Json := do
  let env ← getEnv
  let some info := env.find? entry.declaration
    | throwError "attributed declaration {entry.declaration} is missing"
  unless declarationKind info == "theorem" do
    throwError "attributed declaration {entry.declaration} is not a theorem"
  let wire ← match Proofbound.ExprWire.statementToJson info.type with
    | .ok value => pure value
    | .error message => throwError "cannot encode {entry.declaration}: {message}"
  let axiomSet ← collectAxioms entry.declaration
  -- The protocol orders the serialized strings, not Lean's structural `Name`
  -- representation.  The two orders differ for upper/lower-case components.
  let axiomNames := axiomSet.map (·.toString)
  let axioms := axiomNames.qsort (· < ·) |>.map toJson
  return Json.mkObj [
    ("axioms", Json.arr axioms),
    ("claim_id", entry.claimId),
    ("declaration", entry.declaration.toString),
    ("expr_wire", wire),
    ("kind", declarationKind info),
    ("module", (moduleNameFor env entry.declaration).toString)]

def parseArguments (args : List String) : Except String (Array Name × Array Name) := do
  let mut modules := #[]
  let mut surfaces := #[]
  for arg in args do
    if arg.startsWith "--surface=" then
      let moduleName := arg.drop 10
      if moduleName.isEmpty then throw "empty --surface module"
      surfaces := surfaces.push moduleName.toName
    else if arg.startsWith "-" then
      throw s!"unknown audit argument {arg}"
    else
      modules := modules.push arg.toName
  if modules.isEmpty then throw "at least one Lean module is required"
  return (modules, surfaces)

end Proofbound.Audit

open Proofbound.Audit in
def main (args : List String) : IO UInt32 := do
  let (moduleNames, surfaces) ← match parseArguments args with
    | .ok value => pure value
    | .error message =>
        IO.eprintln s!"proofbound lean audit: {message}"
        return 2
  initSearchPath (← findSysroot)
  let imports := moduleNames.map fun moduleName => { module := moduleName : Import }
  let env ← try importModules imports {}
    catch error =>
      IO.eprintln s!"proofbound lean audit: import failed: {error}"
      return 2
  let entries := (publicClaims env).qsort fun left right =>
    left.declaration.toString < right.declaration.toString
  match validateUniqueIds entries with
  | .error message =>
      IO.eprintln s!"proofbound lean audit: {message}"
      return 2
  | .ok () => pure ()
  let exemptions ← match validateSurfaces env surfaces with
  | .error message =>
      IO.eprintln s!"proofbound lean audit: {message}"
      return 2
  | .ok values => pure values
  let rows ← try
      Prod.fst <$> Core.CoreM.toIO
        (Meta.MetaM.run' (entries.mapM auditEntry))
        { fileName := "<proofbound-audit>", fileMap := default, maxHeartbeats := 2000000000 }
        { env := env }
    catch error =>
      IO.eprintln s!"proofbound lean audit: {error}"
      return 2
  IO.println <| (Json.mkObj [
    ("claims", Json.arr rows),
    ("exemptions", Json.arr exemptions),
    ("schema", "proofbound-lean-audit/1"),
    ("statement_encoding", "lean-expr-cbor/1")]).compress
  return 0
