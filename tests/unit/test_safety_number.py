"""SR-17: safety numbers."""

from __future__ import annotations

from pqchat.protocol.bundle import IdentityKeys
from pqchat.protocol.safety import format_groups, safety_number


def test_same_on_both_sides_and_well_formed() -> None:
    a, b = IdentityKeys.generate().public, IdentityKeys.generate().public
    n = safety_number(a, b)
    assert n == safety_number(b, a)
    assert len(n) == 60 and n.isdigit()
    assert len(format_groups(n)) == 12


def test_changes_when_any_identity_key_changes() -> None:
    """A relay that swaps bob's identity (T-02) produces a different number."""
    alice, bob, mallory = (IdentityKeys.generate().public for _ in range(3))
    assert safety_number(alice, bob) != safety_number(alice, mallory)
