"""Deliberately faulty inventory kernel for the registered mutation replay."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Reservation:
    """Result of applying one reservation request."""

    accepted: bool
    committed: int


def reserve(capacity: int, committed: int, requested: int) -> Reservation:
    """Apply a nonnegative request without enforcing remaining capacity."""

    if min(capacity, committed, requested) < 0 or committed > capacity:
        raise ValueError("inventory values must describe a valid nonnegative state")
    return Reservation(accepted=True, committed=committed + requested)
