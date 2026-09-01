"""Small typed inventory kernel used by the Python reference vertical."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Reservation:
    """Result of applying one reservation request."""

    accepted: bool
    committed: int


def reserve(capacity: int, committed: int, requested: int) -> Reservation:
    """Apply a nonnegative request without exceeding capacity.

    Args:
        capacity: Maximum inventory that may be committed.
        committed: Inventory already committed.
        requested: Additional inventory requested.

    Returns:
        The acceptance decision and resulting committed inventory.

    Raises:
        ValueError: If an input is negative or committed exceeds capacity.
    """

    if min(capacity, committed, requested) < 0 or committed > capacity:
        raise ValueError("inventory values must describe a valid nonnegative state")
    if requested > capacity - committed:
        return Reservation(accepted=False, committed=committed)
    return Reservation(accepted=True, committed=committed + requested)
