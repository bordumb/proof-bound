import Lean

/-!
# Canonical expression wire form

This module exports the presentation-free tree consumed by the Rust Lean
adapter's canonical CBOR encoder. Binder names, source positions, and metadata
are intentionally absent. Free variables and metavariables fail closed.
-/

open Lean

namespace Proofbound.ExprWire

private def arr (values : Array Json) : Json := Json.arr values
private def tag (value : Nat) : Json := toJson value
private def natTransport (value : Nat) : Json := Json.str (toString value)

def binderInfoTag : BinderInfo → Nat
  | .default => 0
  | .implicit => 1
  | .strictImplicit => 2
  | .instImplicit => 3

partial def levelToJson : Level → Except String Json
  | .zero => pure <| arr #[tag 0]
  | .succ level => do pure <| arr #[tag 1, ← levelToJson level]
  | .max left right => do pure <| arr #[tag 2, ← levelToJson left, ← levelToJson right]
  | .imax left right => do pure <| arr #[tag 3, ← levelToJson left, ← levelToJson right]
  | .param name => pure <| arr #[tag 4, Json.str name.toString]
  | .mvar _ => throw "unresolved universe metavariable in public theorem statement"

private def levelsToJson (levels : List Level) : Except String Json :=
  return arr (← levels.toArray.mapM levelToJson)

partial def exprToJson : Expr → Except String Json
  | .bvar index => pure <| arr #[tag 0, natTransport index]
  | .fvar _ => throw "free variable in public theorem statement"
  | .mvar _ => throw "unresolved expression metavariable in public theorem statement"
  | .sort level => do pure <| arr #[tag 1, ← levelToJson level]
  | .const name levels => do pure <| arr #[tag 2, Json.str name.toString, ← levelsToJson levels]
  | .app fn arg => do pure <| arr #[tag 3, ← exprToJson fn, ← exprToJson arg]
  | .lam _ binderType body binderInfo => do
      pure <| arr #[tag 4, tag (binderInfoTag binderInfo), ← exprToJson binderType, ← exprToJson body]
  | .forallE _ binderType body binderInfo => do
      pure <| arr #[tag 5, tag (binderInfoTag binderInfo), ← exprToJson binderType, ← exprToJson body]
  | .letE _ type value body _ => do
      pure <| arr #[tag 6, ← exprToJson type, ← exprToJson value, ← exprToJson body]
  | .lit (.natVal value) => pure <| arr #[tag 7, arr #[tag 0, natTransport value]]
  | .lit (.strVal value) => pure <| arr #[tag 7, arr #[tag 1, Json.str value]]
  | .mdata _ body => exprToJson body
  | .proj typeName index value => do
      pure <| arr #[tag 9, Json.str typeName.toString, natTransport index, ← exprToJson value]

def statementToJson (statement : Expr) : Except String Json :=
  return arr #[Json.str "lean-expr-cbor/1", ← exprToJson statement]

end Proofbound.ExprWire
