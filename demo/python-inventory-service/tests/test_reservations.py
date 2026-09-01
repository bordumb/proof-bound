from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from inventory_service import reserve


def test_rejects_request_beyond_remaining_capacity() -> None:
    result = reserve(capacity=10, committed=7, requested=4)

    assert not result.accepted
    assert result.committed == 7


@given(
    capacity=st.integers(min_value=0, max_value=10_000),
    committed=st.integers(min_value=0, max_value=10_000),
    requested=st.integers(min_value=0, max_value=10_000),
)
def test_accepted_reservation_never_exceeds_capacity(
    capacity: int, committed: int, requested: int
) -> None:
    if committed > capacity:
        return

    result = reserve(capacity, committed, requested)

    assert result.committed <= capacity
    assert result.committed >= committed
