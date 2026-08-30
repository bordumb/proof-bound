import ProofboundDemo.Transfer

namespace ProofboundDemo.KernelBridge

/-!
Transparent handwritten boundary used by the demo before generated Aeneas
modules are present. It deliberately lives outside `lean/Generated/Allowance`.
The translation manifest byte-pins this file and names the import mapping.
-/

structure Request where
  fromBalance : Nat
  toBalance : Nat
  amount : Nat
  cap : Nat
  authorized : Bool
  deriving DecidableEq, Repr

def Request.Valid (request : Request) : Prop :=
  request.fromBalance ≤ ProofboundDemo.Transfer.u64Max ∧
    request.toBalance ≤ ProofboundDemo.Transfer.u64Max ∧
    request.amount ≤ ProofboundDemo.Transfer.u64Max ∧
    request.cap ≤ ProofboundDemo.Transfer.u64Max

def Request.toModel (request : Request) : ProofboundDemo.Transfer.Request := {
  fromBalance := request.fromBalance
  toBalance := request.toBalance
  amount := request.amount
  cap := request.cap
  authorized := request.authorized
}

def decideTransfer (request : Request) : ProofboundDemo.Transfer.Decision :=
  if request.authorized = false then
    ProofboundDemo.Transfer.denied request.toModel .deniedUnauthorized
  else if request.amount = 0 then
    ProofboundDemo.Transfer.denied request.toModel .deniedZeroAmount
  else if request.amount > request.cap then
    ProofboundDemo.Transfer.denied request.toModel .deniedCapExceeded
  else if request.fromBalance < request.amount then
    ProofboundDemo.Transfer.denied request.toModel .deniedInsufficientFunds
  else if request.toBalance + request.amount > ProofboundDemo.Transfer.u64Max then
    ProofboundDemo.Transfer.denied request.toModel .deniedDestinationOverflow
  else {
    code := .accepted
    fromBalance := request.fromBalance - request.amount
    toBalance := request.toBalance + request.amount
  }

end ProofboundDemo.KernelBridge
