"""Shared fixtures: synthetic users with identities and prekeys (PROJECT-BRIEF.md §10)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pqchat.protocol.bundle import IdentityKeys, PrekeyStore

NOW = 1_800_000_000  # fixed clock for deterministic expiry tests (2027-01-15)


def make_store(one_time: int = 2, now: int = NOW) -> PrekeyStore:
    store = PrekeyStore(IdentityKeys.generate())
    store.rotate_signed(now)
    store.add_one_time(one_time, now)
    return store


@pytest.fixture
def new_store() -> Callable[..., PrekeyStore]:
    return make_store


@pytest.fixture(scope="session")
def alice_identity() -> IdentityKeys:
    return IdentityKeys.generate()


@pytest.fixture
def bob() -> PrekeyStore:
    return make_store()
