import ProofboundArtifactDemo.Sha256

/-!
Independent, total, resource-bounded decoder for `FORMAT.md`. The decoder
starts at the exact `ByteArray`; no Rust-decoded values cross the theorem
boundary.
-/

namespace ProofboundArtifactDemo.Certificate

def maxBytes : Nat := 64
def maxEntries : Nat := 8
def maxValue : Nat := 1_000_000

inductive DecodeError where
  | tooLarge
  | truncated
  | badMagic
  | unsupportedVersion
  | nonzeroFlags
  | countRange
  | varintOverflow
  | noncanonicalVarint
  | valueRange
  | idZero
  | idOrder
  | trailingBytes
  deriving DecidableEq, Repr

structure Entry where
  id : Nat
  value : Nat
  deriving DecidableEq, Repr

structure Certificate where
  target : Nat
  entries : List Entry
  deriving DecidableEq, Repr

def Certificate.total (certificate : Certificate) : Nat :=
  certificate.entries.foldl (fun total entry => total + entry.value) 0

private def takeByte : List UInt8 → Except DecodeError (Nat × List UInt8)
  | [] => .error .truncated
  | byte :: rest => .ok (byte.toNat, rest)

private def expectByte (wanted : Nat) (error : DecodeError) (bytes : List UInt8) :
    Except DecodeError (List UInt8) := do
  let (actual, rest) ← takeByte bytes
  if actual = wanted then .ok rest else .error error

private def decodeVarint.go : Nat → List UInt8 → Nat → Nat → Nat →
    Except DecodeError (Nat × List UInt8)
  | 0, _, _, _, _ => .error .varintOverflow
  | fuel + 1, bytes, multiplier, accumulated, groups => do
      let (byte, rest) ← takeByte bytes
      let payload := byte % 128
      if groups = 4 && payload > 15 then
        .error .varintOverflow
      else
        let value := accumulated + payload * multiplier
        if byte < 128 then
          if groups > 0 && payload = 0 then
            .error .noncanonicalVarint
          else
            .ok (value, rest)
        else
          decodeVarint.go fuel rest (multiplier * 128) value (groups + 1)

private def decodeVarint (bytes : List UInt8) : Except DecodeError (Nat × List UInt8) :=
  decodeVarint.go 5 bytes 1 0 0

private def decodeHeader (bytes : List UInt8) : Except DecodeError (Nat × List UInt8) := do
  let bytes ← expectByte 0x50 .badMagic bytes
  let bytes ← expectByte 0x42 .badMagic bytes
  let bytes ← expectByte 0x41 .badMagic bytes
  let bytes ← expectByte 0x43 .badMagic bytes
  let bytes ← expectByte 1 .unsupportedVersion bytes
  let bytes ← expectByte 0 .nonzeroFlags bytes
  let (count, bytes) ← takeByte bytes
  if count = 0 || count > maxEntries then .error .countRange else .ok (count, bytes)

private def decodeEntries : Nat → Nat → List UInt8 →
    Except DecodeError (List Entry × List UInt8)
  | 0, _, bytes => .ok ([], bytes)
  | count + 1, previousId, bytes => do
      let (id, bytes) ← takeByte bytes
      if id = 0 then
        .error .idZero
      else if id ≤ previousId then
        .error .idOrder
      else
        let (value, bytes) ← decodeVarint bytes
        if value > maxValue then
          .error .valueRange
        else
          let (entries, bytes) ← decodeEntries count id bytes
          .ok ({ id, value } :: entries, bytes)

/-- Decode exactly one canonical PBAC byte sequence and reject all trailing data. -/
def decodeList (bytes : List UInt8) : Except DecodeError Certificate :=
  if bytes.length > maxBytes then
    .error .tooLarge
  else do
    let (count, rest) ← decodeHeader bytes
    let (target, rest) ← decodeVarint rest
    if target > maxValue then
      .error .valueRange
    else
      let (entries, rest) ← decodeEntries count 0 rest
      if rest.isEmpty then .ok { target, entries } else .error .trailingBytes

/-- ByteArray convenience boundary used by adapters. -/
def decode (bytes : ByteArray) : Except DecodeError Certificate :=
  decodeList bytes.toList

def checkCertificate (certificate : Certificate) : Bool :=
  decide (certificate.total = certificate.target)

/-- The authoritative Boolean checker over an exact list of octets. -/
def checkList (bytes : List UInt8) : Bool :=
  match decodeList bytes with
  | .error _ => false
  | .ok certificate => checkCertificate certificate

/-- ByteArray convenience boundary used by adapters. -/
def checkBytes (bytes : ByteArray) : Bool := checkList bytes.toList

/-- Domain meaning for this demo: canonical bytes decode to entries whose exact
sum is the certificate's stated target. -/
def MeaningList (bytes : List UInt8) : Prop :=
  ∃ certificate, decodeList bytes = .ok certificate ∧ certificate.total = certificate.target

def Meaning (bytes : ByteArray) : Prop := MeaningList bytes.toList

theorem checkCertificate_sound {certificate : Certificate}
    (accepted : checkCertificate certificate = true) :
    certificate.total = certificate.target := by
  exact of_decide_eq_true accepted

/-- Generic acceptance-implies-meaning theorem, proved without project axioms. -/
theorem checkList_sound {bytes : List UInt8} (accepted : checkList bytes = true) :
    MeaningList bytes := by
  cases decoded : decodeList bytes with
  | error error =>
      unfold checkList at accepted
      rw [decoded] at accepted
      exact Bool.noConfusion accepted
  | ok certificate =>
      refine ⟨certificate, decoded, ?_⟩
      apply checkCertificate_sound
      unfold checkList at accepted
      rw [decoded] at accepted
      exact accepted

theorem checkBytes_sound {bytes : ByteArray} (accepted : checkBytes bytes = true) :
    Meaning bytes :=
  checkList_sound accepted

def acceptsDigest (bytes : List UInt8) (expectedDigest : ByteArray) : Bool :=
  checkList bytes && decide (Sha256.hash (ByteArray.mk bytes.toArray) = expectedDigest)

/-- A digest-conjoined acceptance result establishes both byte meaning and the
literal SHA-256 binding. -/
theorem acceptsDigest_sound {bytes : List UInt8} {expectedDigest : ByteArray}
    (accepted : acceptsDigest bytes expectedDigest = true) :
    MeaningList bytes ∧ Sha256.hash (ByteArray.mk bytes.toArray) = expectedDigest := by
  let digestMatches := decide (Sha256.hash (ByteArray.mk bytes.toArray) = expectedDigest)
  have parts : checkList bytes = true ∧ digestMatches = true :=
    Eq.mp (Bool.and_eq_true (checkList bytes) digestMatches) accepted
  exact ⟨checkList_sound parts.1, of_decide_eq_true parts.2⟩

end ProofboundArtifactDemo.Certificate
