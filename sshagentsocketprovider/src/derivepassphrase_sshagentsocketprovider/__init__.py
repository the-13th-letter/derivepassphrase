# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Definitions for `derivepassphrase`'s SSH agent socket providers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from typing_extensions import NamedTuple, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable

    from typing_extensions import Any, Buffer, TypeAlias

# Semantic versioning.
__version__ = "1.0a1"

# For later major versions, we would choose a different entry point
# group name.
ENTRY_POINT_GROUP_NAME = "derivepassphrase.ssh_agent_socket_providers"


@runtime_checkable
class SSHAgentSocket(Protocol):
    """An abstract networking socket connected to an SSH agent.

    The abstract socket supports the [`sendall`][socket.socket.sendall]
    and a [`recv`][socket.socket.recv] operation, with the same
    signatures and semantics as for "real" sockets.  The abstract socket
    also supports use as a context manager, for automatically closing
    the socket upon exiting the context.

    """

    def __enter__(self) -> Any:  # noqa: ANN401
        """Returns self."""

    # mypy/typeshed has a *very* lax annotation of
    # socket.socket.__exit__, which we need to be compatible with.
    # *sigh*
    def __exit__(self, *args: object) -> bool | None:
        """Closes the socket."""

    def sendall(self, data: Buffer, flags: int = 0, /) -> None:
        """Like [socket.socket.sendall][]."""

    def recv(self, bufsize: int, flags: int = 0, /) -> bytes:
        """Like [socket.socket.recv][]."""


SSHAgentSocketProvider: TypeAlias = "Callable[[], SSHAgentSocket]"
"""A callable that provides an SSH agent socket."""


# For later major versions, we would define a new type.  For minor
# versions, we may add new fields.
class SSHAgentSocketProviderEntry(NamedTuple):
    """Registry information for the table of SSH agent socket providers.

    Third-party developers can register new socket providers for
    auto-discovery by setting up an entry point named
    [`derivepassphrase.ssh_agent_socket_providers`][ENTRY_POINT_GROUP_NAME],
    referencing an instance of this class.  `derivepassphrase` will
    then add appropriate entries to the registry.

    Attributes:
        provider: The callable that provides the socket.
        key: The table key which this entry is registered as.
        aliases: Other keys that shall point to this entry's key.

    Note:
        The socket provider registry table uses the key as the key, and
        the provider as the value. It does not store this info object
        directly.

    """

    provider: SSHAgentSocketProvider
    """"""
    key: str
    """"""
    aliases: tuple[str, ...]
