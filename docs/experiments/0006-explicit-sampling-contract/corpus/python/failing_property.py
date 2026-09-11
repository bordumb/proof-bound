"""Deliberately false property used to verify typed counterexample reporting."""

from hypothesis import strategies


TARGET = "failing_property::nonnegative_integers_are_negative"
STRATEGY = strategies.integers(min_value=0, max_value=10)


def predicate(value: int) -> None:
    """Reject every generated value in the registered bounded domain."""

    assert value < 0
