import Std.Tactic
import ProofboundDemo.Canonical

namespace ProofboundDemo.Transfer

abbrev Request := ProofboundDemo.Canonical.Request

def u64Max : Nat := 18446744073709551615

inductive DecisionCode where
  | accepted
  | deniedUnauthorized
  | deniedZeroAmount
  | deniedCapExceeded
  | deniedInsufficientFunds
  | deniedDestinationOverflow
  deriving DecidableEq, Repr

def DecisionCode.toUInt8 : DecisionCode → UInt8
  | .accepted => 0
  | .deniedUnauthorized => 1
  | .deniedZeroAmount => 2
  | .deniedCapExceeded => 3
  | .deniedInsufficientFunds => 4
  | .deniedDestinationOverflow => 5

structure Decision where
  code : DecisionCode
  fromBalance : Nat
  toBalance : Nat
  deriving DecidableEq, Repr

def denied (request : Request) (code : DecisionCode) : Decision := {
  code
  fromBalance := request.fromBalance
  toBalance := request.toBalance
}

/-!
The rich model uses natural numbers but retains the shipping kernel's explicit
`u64` destination-overflow guard. Values decoded from the canonical format are
bounded by construction.
-/
def decide (request : Request) : Decision :=
  if request.authorized = false then
    denied request .deniedUnauthorized
  else if request.amount = 0 then
    denied request .deniedZeroAmount
  else if request.amount > request.cap then
    denied request .deniedCapExceeded
  else if request.fromBalance < request.amount then
    denied request .deniedInsufficientFunds
  else if request.toBalance + request.amount > u64Max then
    denied request .deniedDestinationOverflow
  else {
    code := .accepted
    fromBalance := request.fromBalance - request.amount
    toBalance := request.toBalance + request.amount
  }

theorem accept_conserves {request : Request} {result : Decision}
    (hDecision : decide request = result)
    (hAccepted : result.code = .accepted) :
    result.fromBalance + result.toBalance =
      request.fromBalance + request.toBalance := by
  unfold decide at hDecision
  split at hDecision
  · subst result
    cases hAccepted
  · split at hDecision
    · subst result
      cases hAccepted
    · split at hDecision
      · subst result
        cases hAccepted
      · split at hDecision
        · subst result
          cases hAccepted
        · split at hDecision
          · subst result
            cases hAccepted
          · subst result
            change request.fromBalance - request.amount +
              (request.toBalance + request.amount) =
                request.fromBalance + request.toBalance
            omega

theorem accept_never_overdraws {request : Request} {result : Decision}
    (hDecision : decide request = result)
    (hAccepted : result.code = .accepted) :
    request.amount ≤ request.fromBalance ∧
      result.fromBalance = request.fromBalance - request.amount := by
  unfold decide at hDecision
  split at hDecision
  · subst result
    cases hAccepted
  · split at hDecision
    · subst result
      cases hAccepted
    · split at hDecision
      · subst result
        cases hAccepted
      · split at hDecision
        · subst result
          cases hAccepted
        · split at hDecision
          · subst result
            cases hAccepted
          · subst result
            exact ⟨by omega, rfl⟩

theorem accept_respects_cap {request : Request} {result : Decision}
    (hDecision : decide request = result)
    (hAccepted : result.code = .accepted) :
    request.amount ≤ request.cap := by
  unfold decide at hDecision
  split at hDecision
  · subst result
    cases hAccepted
  · split at hDecision
    · subst result
      cases hAccepted
    · split at hDecision
      · subst result
        cases hAccepted
      · split at hDecision
        · subst result
          cases hAccepted
        · split at hDecision
          · subst result
            cases hAccepted
          · subst result
            omega

theorem denial_unchanged {request : Request} {result : Decision}
    (hDecision : decide request = result)
    (hDenied : result.code ≠ .accepted) :
    result.fromBalance = request.fromBalance ∧
      result.toBalance = request.toBalance := by
  unfold decide at hDecision
  split at hDecision
  · subst result
    exact ⟨rfl, rfl⟩
  · split at hDecision
    · subst result
      exact ⟨rfl, rfl⟩
    · split at hDecision
      · subst result
        exact ⟨rfl, rfl⟩
      · split at hDecision
        · subst result
          exact ⟨rfl, rfl⟩
        · split at hDecision
          · subst result
            exact ⟨rfl, rfl⟩
          · subst result
            exact (hDenied rfl).elim

end ProofboundDemo.Transfer
