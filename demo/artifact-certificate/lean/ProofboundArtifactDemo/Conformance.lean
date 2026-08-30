import ProofboundArtifactDemo.Claims

/-! Kernel-reduced boundary examples for the independent Lean decoder. -/

namespace ProofboundArtifactDemo.Conformance

open ProofboundArtifactDemo.Certificate
open ProofboundArtifactDemo.Claims

def noncanonicalTarget : List UInt8 := [
  0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x87, 0x00,
  0x01, 0x03, 0x04, 0x80, 0x01, 0x09, 0xfa, 0x06]

def trailingByte : List UInt8 := publishedBytes ++ [0]

def duplicateId : List UInt8 := [
  0x50, 0x42, 0x41, 0x43, 0x01, 0x00, 0x03, 0xfd, 0x07,
  0x01, 0x03, 0x01, 0x80, 0x01, 0x09, 0xfa, 0x06]

def rejectsAs (expected : DecodeError) (bytes : List UInt8) : Bool :=
  match decodeList bytes with
  | .error actual => decide (actual = expected)
  | .ok _ => false

example : rejectsAs .noncanonicalVarint noncanonicalTarget = true := by decide
example : rejectsAs .trailingBytes trailingByte = true := by decide
example : rejectsAs .idOrder duplicateId = true := by decide
example : checkList publishedBytes = true := by decide

end ProofboundArtifactDemo.Conformance
