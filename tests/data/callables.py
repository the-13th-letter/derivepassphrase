# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""General machinery for `derivepassphrase` testing data.

This module contains machinery supplementary to the data from the
`tests.data` module, such as common dummy functions, or simple parsers
for (the restricted format in use by) the data.  It also contains some
actual test data that needs to be generated programmatically, or that
e.g. includes a function from this module as an embedded callback
parameter.

"""

from __future__ import annotations

import os
import shlex
import stat
from typing import TYPE_CHECKING

import derivepassphrase_sshagentsocketprovider as d_sasp
import tests.data
from derivepassphrase import _types, ssh_agent, vault

__all__ = ()

if TYPE_CHECKING:
    import socket
    from collections.abc import Generator

    from typing_extensions import Any


# Stubbed actions
# ===============


# SSH agent client
# ----------------


def list_keys(self: Any = None) -> list[_types.SSHKeyCommentPair]:
    """Return a list of all SSH test keys, as key/comment pairs.

    Intended as a monkeypatching replacement for
    [`ssh_agent.SSHAgentClient.list_keys`][].

    """
    del self  # Unused.
    Pair = _types.SSHKeyCommentPair  # noqa: N806
    return [
        Pair(value.public_key_data, f"{key} test key".encode("ASCII"))
        for key, value in tests.data.ALL_KEYS.items()
    ]


def sign(
    self: Any, key: bytes | bytearray, message: bytes | bytearray
) -> bytes:
    """Return the signature of `message` under `key`.

    Can only handle keys in [`SUPPORTED_KEYS`][], and only the vault
    UUID as the message.

    Intended as a monkeypatching replacement for
    [`ssh_agent.SSHAgentClient.sign`][].

    """
    del self  # Unused.
    assert message == vault.Vault.UUID
    for value in tests.data.SUPPORTED_KEYS.values():
        if value.public_key_data == key:  # pragma: no branch
            return value.expected_signatures[
                tests.data.SSHTestKeyDeterministicSignatureClass.SPEC
            ].signature
    raise AssertionError


def list_keys_singleton(self: Any = None) -> list[_types.SSHKeyCommentPair]:
    """Return a singleton list of the first supported SSH test key.

    The key is returned as a key/comment pair.

    Intended as a monkeypatching replacement for
    [`ssh_agent.SSHAgentClient.list_keys`][].

    """
    del self  # Unused.
    Pair = _types.SSHKeyCommentPair  # noqa: N806
    list1 = [
        Pair(value.public_key_data, f"{key} test key".encode("ASCII"))
        for key, value in tests.data.SUPPORTED_KEYS.items()
    ]
    return list1[:1]


# CLI machinery
# -------------


def suitable_ssh_keys(
    conn: Any,
) -> Generator[_types.SSHKeyCommentPair, None, None]:
    """Return a two-item list of SSH test keys (key/comment pairs).

    Intended as a monkeypatching replacement for
    `cli_machinery.get_suitable_ssh_keys` to better script and test the
    interactive key selection.  When used this way, `derivepassphrase`
    believes that only those two keys are loaded and suitable.

    """
    del conn  # Unused.
    Pair = _types.SSHKeyCommentPair  # noqa: N806
    yield from [
        Pair(tests.data.DUMMY_KEY1, b"no comment"),
        Pair(tests.data.DUMMY_KEY2, b"a comment"),
    ]


def auto_prompt(*args: Any, **kwargs: Any) -> str:
    """Return [`DUMMY_PASSPHRASE`][].

    Intended as a monkeypatching replacement for
    `cli.prompt_for_passphrase` to better script and test the
    interactive passphrase queries.

    """
    del args, kwargs  # Unused.
    return tests.data.DUMMY_PASSPHRASE


# `vault` module
# --------------


def phrase_from_key(
    key: bytes,
    /,
    *,
    conn: ssh_agent.SSHAgentClient | socket.socket | None = None,
) -> bytes:
    """Return the "equivalent master passphrase" for key.

    Only works for key [`DUMMY_KEY1`][].

    Intended as a monkeypatching replacement for
    [`vault.Vault.phrase_from_key`][], bypassing communication with an
    actual SSH agent.

    """
    del conn
    if key == tests.data.DUMMY_KEY1:  # pragma: no branch
        return tests.data.DUMMY_PHRASE_FROM_KEY1
    raise KeyError(key)  # pragma: no cover


# SSH agent socket provider data (with callables)
# ===============================================


def provider_entry_provider() -> d_sasp.SSHAgentSocket:  # pragma: no cover
    """A pseudo provider for a [`_types.SSHAgentSocketProviderEntry`][]."""
    msg = "We are not supposed to be called!"
    raise AssertionError(msg)


provider_entry1 = d_sasp.SSHAgentSocketProviderEntry(
    provider_entry_provider, "entry1", ("entry1a", "entry1b", "entry1c")
)
"""A sample [`_types.SSHAgentSocketProviderEntry`][]."""

provider_entry2 = d_sasp.SSHAgentSocketProviderEntry(
    provider_entry_provider, "entry2", ("entry2d", "entry2e")
)


# SSH agent output parsing
# ========================


def parse_sh_export_line(line: str, *, env_name: str) -> str:
    """Parse the output of typical SSH agents' SSH_AUTH_SOCK lines.

    Intentionally parses only a small subset of sh(1) syntax which works
    with current OpenSSH and PuTTY output.  We require exactly one
    variable setting, and one export instruction, both on the same line,
    and perhaps combined into one statement.  Terminating semicolons
    after each command are ignored.

    Args:
        line:
            A line of sh(1) script to parse.
        env_name:
            The name of the environment variable to expect.

    Returns:
        The parsed environment variable value.

    Raises:
        ValueError:
            Cannot parse the sh script.  Perhaps it is too complex,
            perhaps it is malformed.

    """
    line = line.rstrip("\r\n")
    shlex_parser = shlex.shlex(
        instream=line, posix=True, punctuation_chars=True
    )
    shlex_parser.whitespace = " \t"
    tokens = list(shlex_parser)
    orig_tokens = tokens.copy()
    if tokens[-1] == ";":
        tokens.pop()
    if tokens[-3:] == [";", "export", env_name]:
        tokens[-3:] = []
        tokens[:0] = ["export"]
    if not (
        len(tokens) == 2
        and tokens[0] == "export"
        and tokens[1].startswith(f"{env_name}=")
    ):
        msg = f"Cannot parse sh line: {orig_tokens!r} -> {tokens!r}"
        raise ValueError(msg)
    return tokens[1].split("=", 1)[1]


# General file system actions
# ===========================


def make_file_readonly(
    pathname: str | bytes | os.PathLike[str],
    /,
    *,
    try_race_free_implementation: bool = True,
) -> None:
    """Mark a file as read-only.

    On POSIX, this entails removing the write permission bits for user,
    group and other, and ensuring the read permission bit for user is
    set.

    Unfortunately, The Annoying OS (a.k.a. Microsoft Windows) has its
    own rules: Set exactly(?) the read permission bit for user to make
    the file read-only, and set exactly(?) the write permission bit for
    user to make the file read/write; all other permission bit settings
    are ignored.

    The cross-platform procedure therefore is:

    1. Call `os.stat` on the file, noting the permission bits.
    2. Calculate the new permission bits POSIX-style.
    3. Call `os.chmod` with permission bit `stat.S_IREAD`.
    4. Call `os.chmod` with the correct POSIX-style permissions.

    If the platform supports it, we use a file descriptor instead of
    a path name.  Otherwise, we use the same path name multiple times,
    and are susceptible to race conditions.

    """
    fname: int | str | bytes | os.PathLike
    if try_race_free_implementation and {os.stat, os.chmod} <= os.supports_fd:
        # The Annoying OS (v11 at least) supports fstat and fchmod, but
        # does not support changing the file mode on file descriptors
        # for read-only files.
        fname = os.open(
            pathname,
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOCTTY", 0),
        )
    else:
        fname = pathname
    try:
        orig_mode = os.stat(fname).st_mode  # noqa: PTH116
        new_mode = (
            orig_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH
            | stat.S_IREAD
        )
        os.chmod(fname, stat.S_IREAD)  # noqa: PTH101
        os.chmod(fname, new_mode)  # noqa: PTH101
    finally:
        if isinstance(fname, int):
            os.close(fname)
