# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for `derivepassphrase.ssh_agent`: heavy-duty tests."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest
from hypothesis import stateful, strategies

from derivepassphrase.ssh_agent import socketprovider
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from derivepassphrase import _types

# All tests in this module are heavy-duty tests.
pytestmark = [pytest_machinery.heavy_duty]


@strategies.composite
def draw_alias_chain(
    draw: strategies.DrawFn,
    *,
    known_keys_strategy: strategies.SearchStrategy[str],
    new_keys_strategy: strategies.SearchStrategy[str],
    chain_size: strategies.SearchStrategy[int] = strategies.integers(  # noqa: B008
        min_value=1,
        max_value=5,
    ),
    existing: bool = False,
) -> tuple[str, ...]:
    """Draw names for alias chains in the SSH agent socket provider registry.

    Depending on arguments, draw a set of names from the new keys bundle
    that do not yet exist in the registry, to insert as a new alias
    chain.  Alternatively, draw a non-alias name from the known keys
    bundle, then draw other names that either don't exist yet in the
    registry, or that alias the first name directly or indirectly.  The
    chain length, and whether to target existing registry entries or
    not, may be set statically, or may be drawn from a respective
    strategy.

    Args:
        draw:
            The `hypothesis` draw function.
        chain_size:
            A strategy for determining the correct alias chain length.
            Must not yield any integers less than 1.
        existing:
            If true, target an existing registry entry in the alias
            chain, and permit rewriting existing aliases of that same
            entry to the new alias.  Otherwise, draw only new names.
        known_keys_strategy:
            A strategy for generating provider registry keys already
            contained in the registry.  Typically, this is
            a [Bundle][hypothesis.stateful.Bundle].
        new_keys_strategy:
            A strategy for generating provider registry keys not yet
            contained in the registry with high probability.  Typically,
            this is a [consuming][hypothesis.stateful.consumes]
            [Bundle][hypothesis.stateful.Bundle].

    Returns:
        A tuple of names forming an alias chain, each entry pointing to
        or intending to point to the previous entry in the tuple.

    """
    registry = socketprovider.SocketProvider.registry

    def not_an_alias(key: str) -> bool:
        return key in registry and not isinstance(registry[key], str)

    def is_indirect_alias_of(
        key: str, target: str
    ) -> bool:  # pragma: no cover
        if key == target:
            return False  # not an alias
        seen = set()  # loop detection
        while key not in seen:
            seen.add(key)
            if key not in registry:
                return False
            if not isinstance(registry[key], str):
                return False
            if key == target:
                return True
            tmp = registry[key]
            assert isinstance(tmp, str)
            key = tmp
        return False  # loop

    err_msg_chain_size = "Chain sizes must always be 1 or larger."

    size = draw(chain_size, label="chain_size")
    if size < 1:  # pragma: no cover
        raise ValueError(err_msg_chain_size)
    names: list[str] = []
    base: str | None = None
    if existing:
        names.append(
            draw(known_keys_strategy.filter(not_an_alias), label="base")
        )
        base = names[0]
        size -= 1
        new_key_strategy = new_keys_strategy.filter(
            lambda key: key not in registry
        )
        old_key_strategy = known_keys_strategy.filter(
            lambda key: is_indirect_alias_of(key, target=base)
        )
        list_strategy_source = strategies.one_of(
            new_key_strategy, old_key_strategy
        )
    else:
        list_strategy_source = new_keys_strategy.filter(
            lambda key: key not in registry
        )
    list_strategy = strategies.lists(
        list_strategy_source.filter(lambda candidate: candidate != base),
        min_size=size,
        max_size=size,
        unique=True,
    )
    names.extend(draw(list_strategy, label="others"))
    return tuple(names)


class SSHAgentSocketProviderRegistryStateMachine(
    stateful.RuleBasedStateMachine
):
    """A state machine for the SSH agent socket provider registry.

    Record possible changes to the socket provider registry, keeping track
    of true entries, aliases, and reservations.

    """

    def __init__(self) -> None:
        """Initialize self, set up context managers and enter them."""
        super().__init__()
        self.exit_stack = contextlib.ExitStack().__enter__()
        self.monkeypatch = self.exit_stack.enter_context(
            pytest.MonkeyPatch.context()
        )
        self.orig_registry = socketprovider.SocketProvider.registry
        self.registry: dict[
            str, _types.SSHAgentSocketProvider | str | None
        ] = {
            "ssh_auth_sock_on_posix": self.orig_registry["ssh_auth_sock_on_posix"],
            "pageant_on_the_annoying_os": self.orig_registry["pageant_on_the_annoying_os"],
            "native": self.orig_registry["native"],
            "posix": "ssh_auth_sock_on_posix",
            "the_annoying_os": "pageant_on_the_annoying_os",
        }
        self.monkeypatch.setattr(
            socketprovider.SocketProvider, "registry", self.registry
        )
        self.model: dict[str, _types.SSHAgentSocketProvider | None] = {}

    known_keys: stateful.Bundle[str] = stateful.Bundle("known_keys")
    """"""
    new_keys: stateful.Bundle[str] = stateful.Bundle("new_keys")
    """"""

    def sample_provider(self) -> _types.SSHAgentSocket:
        raise AssertionError

    @stateful.initialize(
        target=known_keys,
    )
    def get_registry_keys(self) -> stateful.MultipleResults[str]:
        """Read the standard keys from the registry."""
        self.model.update({
            k: socketprovider.SocketProvider.lookup(k) for k in self.registry
        })
        return stateful.multiple(*self.registry.keys())

    @stateful.rule(
        target=new_keys,
        k=strategies.text("abcdefghijklmnopqrstuvwxyz0123456789_").filter(
            lambda s: s not in socketprovider.SocketProvider.registry
        ),
    )
    def new_key(self, k: str) -> str:
        return k

    @stateful.invariant()
    def check_consistency(self) -> None:
        lookup = socketprovider.SocketProvider.lookup
        assert self.registry.keys() == self.model.keys()
        for k in self.model:
            resolved = lookup(k)
            modelled = self.model[k]
            step1 = self.registry[k]
            manually = lookup(step1) if isinstance(step1, str) else step1
            assert resolved == modelled
            assert resolved == manually

    @stateful.rule(
        target=known_keys,
        chain=draw_alias_chain(
            known_keys_strategy=known_keys,
            new_keys_strategy=stateful.consumes(new_keys),
            existing=True,
        ),
    )
    def alias_existing(
        self, chain: tuple[str, ...]
    ) -> stateful.MultipleResults[str]:
        try:
            provider = socketprovider.SocketProvider.resolve(chain[0])
        except NotImplementedError:  # pragma: no cover [failsafe]
            provider = self.sample_provider
        assert (
            socketprovider.SocketProvider.register(*chain)(provider)
            == provider
        )
        for k in chain:
            self.model[k] = provider
        return stateful.multiple(*chain[1:])

    @stateful.rule(
        target=known_keys,
        chain=draw_alias_chain(
            known_keys_strategy=known_keys,
            new_keys_strategy=stateful.consumes(new_keys),
            existing=False,
        ),
    )
    def alias_new(self, chain: list[str]) -> stateful.MultipleResults[str]:
        provider = self.sample_provider
        assert (
            socketprovider.SocketProvider.register(*chain)(provider)
            == provider
        )
        for k in chain:
            self.model[k] = provider
        return stateful.multiple(*chain)

    def teardown(self) -> None:
        """Upon teardown, exit all contexts entered in `__init__`."""
        self.exit_stack.close()


TestSSHAgentSocketProviderRegistry = (
    SSHAgentSocketProviderRegistryStateMachine.TestCase
)
