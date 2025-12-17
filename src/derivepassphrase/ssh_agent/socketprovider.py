# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Machinery for providing sockets connected to SSH agents."""

from __future__ import annotations

import collections
import ctypes
import os
import socket
from typing import TYPE_CHECKING, ClassVar, cast

if TYPE_CHECKING:
    from collections.abc import Callable

    from derivepassphrase import _types

__all__ = ("SocketProvider",)


class NoSuchProviderError(KeyError):
    """No such SSH agent socket provider is known."""


class UnixDomainSocketsNotAvailableError(NotImplementedError):
    """This Python installation does not support UNIX domain sockets.

    On this installation, the standard library symbol
    [`socket.AF_UNIX`][] is not available, necessary to create UNIX
    domain sockets.

    """


class WindowsNamedPipesNotAvailableError(NotImplementedError):
    """This Python installation does not support Windows named pipes."""


class SocketProvider:
    """Static functionality for providing sockets."""

    @staticmethod
    def unix_domain_ssh_auth_sock(*, timeout: int = 125) -> socket.socket:
        """Return a UNIX domain socket connected to `SSH_AUTH_SOCK`.

        Args:
            timeout:
                A connection timeout for the SSH agent.  Only used for
                "true" sockets, and only if the socket is not yet connected.
                The default value gives ample time for agent connections
                forwarded via SSH on high-latency networks (e.g. Tor).

        Returns:
            A connected UNIX domain socket.

        Raises:
            KeyError:
                The `SSH_AUTH_SOCK` environment variable was not found.
            UnixDomainSocketsNotAvailableError:
                This Python version does not support UNIX domain
                sockets, necessary to automatically connect to
                a running SSH agent via the `SSH_AUTH_SOCK` environment
                variable.
            OSError:
                There was an error setting up a socket connection to the
                agent.

        """
        if not hasattr(socket, "AF_UNIX"):
            msg = "This Python version does not support UNIX domain sockets."
            raise UnixDomainSocketsNotAvailableError(msg)
        else:  # noqa: RET506  # pragma: unless posix no cover
            sock = socket.socket(family=socket.AF_UNIX)
            if "SSH_AUTH_SOCK" not in os.environ:
                msg = "SSH_AUTH_SOCK environment variable"
                raise KeyError(msg)
            ssh_auth_sock = os.environ["SSH_AUTH_SOCK"]
            sock.settimeout(timeout)
            sock.connect(ssh_auth_sock)
            return sock

    @staticmethod
    def windows_named_pipe() -> _types.SSHAgentSocket:
        """Return a socket connected to Pageant/OpenSSH on The Annoying OS.

        This may be a write-through socket if the underlying connection
        to Pageant or OpenSSH does not use an actual network socket to
        communicate.

        Raises:
            WindowsNamedPipesNotAvailableError:
                This functionality is not implemented yet.

        Warning: Not implemented yet
            This functionality is not implemented yet.  Specifically,
            [we do not yet support any of the communication mechanisms
            used by the leading SSH agent
            implementations.][windows-ssh-agent-support]

            [windows-ssh-agent-support]: https://the13thletter.info/derivepassphrase/0.x/wishlist/windows-ssh-agent-support/

        """
        if not hasattr(ctypes, "WinDLL"):
            msg = "This Python version does not support Windows named pipes."
            raise WindowsNamedPipesNotAvailableError(msg)
        else:  # noqa: RET506  # pragma: unless the-annoying-os no cover
            msg = (
                "Communicating with Pageant or OpenSSH on Windows "
                "is not implemented yet."
            )
            raise NotImplementedError(msg)

    registry: ClassVar[
        dict[str, _types.SSHAgentSocketProvider | str | None]
    ] = {}
    """A dictionary of callables that provide SSH agent sockets.

    Each entry in the dictionary points either to a callable, a string,
    or `None`: if a callable, then that callable returns a socket; if
    a string, then this entry is an alias for that other entry; if
    `None`, then the entry name is merely registered, but no
    implementation is available.

    If a callable is not applicable to this platform, Python
    installation or `derivepassphrase` installation, then it MUST raise
    [`NotImplementedError`][].  Conversely, if the callable returns
    a value, or raises any other kind of exception, then the caller MAY
    assume that this platform, Python installation and
    `derivepassphrase` installation are sufficient for the callable to
    be able to return a working socket on this platform.  (The latter
    may still be dependent on further, external circumstances, such as
    required configuration settings, or environment variables, or
    sufficient system resources, etc.)

    (Interpretation of "MUST" and "MAY" as per IETF Best Current
    Practice #14; see [RFC 2119][] and [RFC 8174][].)

    [RFC 2119]: https://www.rfc-editor.org/info/rfc2119
    [RFC 8174]: https://www.rfc-editor.org/info/rfc8174

    """

    @classmethod
    def register(
        cls,
        name: str,
        *aliases: str,
    ) -> Callable[
        [_types.SSHAgentSocketProvider], _types.SSHAgentSocketProvider
    ]:
        """Register a callable as an SSH agent socket provider (decorator).

        Attempting to re-register an existing alias, or a name with an
        implementation, with a different implementation is an error.

        Args:
            name:
                The principal name under which to register the passed
                callable.
            aliases:
                Alternate names to register as aliases for the principal
                name.

        Returns:
            A decorator implementing the above.

        """

        def decorator(
            f: _types.SSHAgentSocketProvider,
        ) -> _types.SSHAgentSocketProvider:
            """Register a callable as an SSH agent socket provider.

            Attempting to re-register an existing alias, or a name with
            an implementation, with a different implementation is an
            error.

            Args:
                f: The callable to decorate/register.

            Returns:
                The callable.

            Raises:
                ValueError:
                    The name or alias is already in use.

            """
            for alias in [name, *aliases]:
                try:
                    existing = cls.lookup(alias)
                except (NoSuchProviderError, NotImplementedError):
                    cls.registry[alias] = f if alias == name else name
                else:
                    if existing is None:
                        cls.registry[alias] = f if alias == name else name
                    elif existing != f:
                        msg = (
                            f"The SSH agent socket provider {alias!r} "
                            f"is already registered."
                        )
                        raise ValueError(msg)
            return f

        return decorator

    @classmethod
    def lookup(
        cls, provider: _types.SSHAgentSocketProvider | str | None, /
    ) -> _types.SSHAgentSocketProvider | None:
        """Look up a socket provider entry.

        Args:
            provider: The provider to look up.

        Returns:
            The callable indicated by this provider, if it is
            implemented, or `None`, if it is merely registered.

        Raises:
            NoSuchProviderError:
                The provider is not registered.

        """
        ret = provider
        while isinstance(ret, str):
            try:
                ret = cls.registry[ret]
            except KeyError as exc:
                raise NoSuchProviderError(ret) from exc
        return ret

    @classmethod
    def resolve(
        cls, provider: _types.SSHAgentSocketProvider | str | None, /
    ) -> _types.SSHAgentSocketProvider:
        """Resolve a socket provider to a proper callable.

        Args:
            provider: The provider to resolve.

        Returns:
            The callable indicated by this provider.

        Raises:
            NoSuchProviderError:
                The provider is not registered.
            NotImplementedError:
                The provider is registered, but is not functional or not
                applicable to this `derivepassphrase` installation.

        """
        ret = cls.lookup(provider)
        if ret is None:
            msg = (
                f"The {ret!r} socket provider is not functional on or "
                "not applicable to this derivepassphrase installation."
            )
            raise NotImplementedError(msg)
        return ret

    ENTRY_POINT_GROUP_NAME = "derivepassphrase.ssh_agent_socket_providers"
    """
    The group name under which [entry
    points][importlib.metadata.entry_points] for the SSH agent socket
    provider registry should be recorded.  Each target of such an entry
    point should be a [`_types.SSHAgentSocketProviderEntry`][] object.
    """

    @classmethod
    def _find_all_ssh_agent_socket_providers(cls) -> None:
        """Find and load all declared SSH agent socket providers.

        Load all [entry points][importlib.metadata.entry_points] in the
        `derivepassphrase.ssh_agent_socket_providers` group as providers,
        then register them.  The target of each entry point should be
        a [`_types.SSHAgentSocketProviderEntry`][] object.

        Raises:
            AssertionError:
                The declared SSH agent socket provider was not, in fact,
                an SSH agent socket provider.

                Alternatively, multiple distributions supplied the same
                SSH agent socket provider, but with different
                implementations.

        """
        import importlib.metadata  # noqa: PLC0415

        origins: dict[str, str | None] = {}
        entries = collections.ChainMap({}, cls.registry)
        for entry_point in importlib.metadata.entry_points(
            group=cls.ENTRY_POINT_GROUP_NAME
        ):
            provider_entry = cast(
                "_types.SSHAgentSocketProviderEntry", entry_point.load()
            )
            key = provider_entry.key
            value = entry_point.value
            dist = (
                entry_point.dist.name  # type: ignore[union-attr]
                if getattr(entry_point, "dist", None) is not None
                else None
            )
            origin = origins.get(key, "derivepassphrase")
            if not callable(provider_entry.provider):
                msg = (
                    f"Not an SSHAgentSocketProvider: "
                    f"{dist = }, {cls.ENTRY_POINT_GROUP_NAME = }, "
                    f"{value = }, {provider_entry = }"
                )
                raise AssertionError(msg)  # noqa: TRY004
            if key in entries:
                if entries[key] != provider_entry.provider:
                    msg = (
                        f"Name clash in SSH agent socket providers "
                        f"for entry {key!r}, both by {dist!r} "
                        f"and by {origin!r}"
                    )
                    raise AssertionError(msg)
            else:
                entries[key] = provider_entry.provider
                origins[key] = dist
            for alias in provider_entry.aliases:
                alias_origin = origins.get(alias, "derivepassphrase")
                if alias in entries:
                    if entries[alias] != key:
                        msg = (
                            f"Name clash in SSH agent socket providers "
                            f"for entry {alias!r}, both by {dist!r} "
                            f"and by {alias_origin!r}"
                        )
                        raise AssertionError(msg)
                else:
                    entries[alias] = key
                    origins[key] = dist
        cls.registry.update(entries.maps[0])


SocketProvider.registry.update({
    "posix": SocketProvider.unix_domain_ssh_auth_sock,
    "the_annoying_os": SocketProvider.windows_named_pipe,
    # known instances
    "stub_agent": None,
    "stub_with_address": None,
    "stub_with_address_and_deterministic_dsa": None,
    # aliases
    "native": "the_annoying_os" if os.name == "nt" else "posix",
    "unix_domain": "posix",
    "ssh_auth_sock": "posix",
    "the_annoying_os_named_pipe": "the_annoying_os",
    "pageant_on_the_annoying_os": "the_annoying_os",
    "openssh_on_the_annoying_os": "the_annoying_os",
    "windows": "the_annoying_os",
    "windows_named_pipe": "the_annoying_os",
    "pageant_on_windows": "the_annoying_os",
    "openssh_on_windows": "the_annoying_os",
})
