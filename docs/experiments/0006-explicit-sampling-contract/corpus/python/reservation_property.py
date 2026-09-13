from __future__ import annotations

from hypothesis import strategies as st

from inventory_service import reserve


TARGET = "reservation_property::accepted_reservation_never_exceeds_capacity"
STRATEGY = st.tuples(
    st.integers(min_value=0, max_value=10_000),
    st.integers(min_value=0, max_value=10_000),
    st.integers(min_value=0, max_value=10_000),
)


def predicate(value: tuple[int, int, int]) -> None:
    """Check that an accepted reservation remains within capacity."""

    capacity, committed, requested = value
    if committed > capacity:
        return
    result = reserve(capacity, committed, requested)
    assert result.committed <= capacity
    assert result.committed >= committed
