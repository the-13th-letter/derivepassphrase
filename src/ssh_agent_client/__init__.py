# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""A bare-bones SSH agent client supporting signing and key listing."""

from __future__ import annotations

import collections
import enum
import errno
import os
import pathlib
import socket

from collections.abc import Sequence, MutableSequence
from typing import Any, NamedTuple, Self, TypeAlias
from ssh_agent_client.types import KeyCommentPair, SSH_AGENT, SSH_AGENTC

__all__ = ('SSHAgentClient',)
__author__ = 'Marco Ricci <m@the13thletter.info>'
__version__ = "0.1.0"

_socket = socket

class TrailingDataError(RuntimeError):
    """The result contained trailing data."""

class SSHAgentClient:
    """A bare-bones SSH agent client supporting signing and key listing.

    The main use case is requesting the agent sign some data, after
    checking that the necessary key is already loaded.

    The main fleshed out methods are `list_keys` and `sign`, which
    implement the `REQUEST_IDENTITIES` and `SIGN_REQUEST` requests.  If
    you *really* wanted to, there is enough infrastructure in place to
    issue other requests as defined in the protocol---it's merely the
    wrapper functions and the protocol numbers table that are missing.

    """
    _connection: socket.socket
    def __init__(
        self, /, *, socket: socket.socket | None = None, timeout: int = 125
    ) -> None:
        """Initialize the client.

        Args:
            socket:
                An optional socket, connected to the SSH agent.  If not
                given, we query the `SSH_AUTH_SOCK` environment
                variable to auto-discover the correct socket address.
            timeout:
                A connection timeout for the SSH agent.  Only used if
                the socket is not yet connected.  The default value
                gives ample time for agent connections forwarded via
                SSH on high-latency networks (e.g. Tor).

        """
        if socket is not None:
            self._connection = socket
        else:
            self._connection = _socket.socket(family=_socket.AF_UNIX)
        try:
            # Test whether the socket is connected.
            self._connection.getpeername()
        except OSError as e:
            # This condition is hard to test purposefully, so exclude
            # from coverage.
            if e.errno != errno.ENOTCONN:  # pragma: no cover
                raise
            try:
                ssh_auth_sock = os.environ['SSH_AUTH_SOCK']
            except KeyError as e:
                raise RuntimeError(
                    "Can't find running ssh-agent: missing SSH_AUTH_SOCK"
                ) from e
            self._connection.settimeout(timeout)
            try:
                self._connection.connect(ssh_auth_sock)
            except FileNotFoundError as e:
                raise RuntimeError(
                    "Can't find running ssh-agent: unusable SSH_AUTH_SOCK"
                ) from e

    def __enter__(self) -> Self:
        """Close socket connection upon context manager completion."""
        self._connection.__enter__()
        return self

    def __exit__(
        self, exc_type: Any, exc_val: Any, exc_tb: Any
    ) -> bool:
        """Close socket connection upon context manager completion."""
        return bool(
            self._connection.__exit__(
                exc_type, exc_val, exc_tb)  # type: ignore[func-returns-value]
        )

    @staticmethod
    def uint32(num: int, /) -> bytes:
        r"""Format the number as a `uint32`, as per the agent protocol.

        Args:
            num: A number.

        Returns:
            The number in SSH agent wire protocol format, i.e. as
            a 32-bit big endian number.

        Raises:
            OverflowError:
                As per [`int.to_bytes`][].

        Examples:
            >>> SSHAgentClient.uint32(16777216)
            b'\x01\x00\x00\x00'

        """
        return int.to_bytes(num, 4, 'big', signed=False)

    @classmethod
    def string(cls, payload: bytes | bytearray, /) -> bytes | bytearray:
        r"""Format the payload as an SSH string, as per the agent protocol.

        Args:
            payload: A byte string.

        Returns:
            The payload, framed in the SSH agent wire protocol format.

        Examples:
            >>> bytes(SSHAgentClient.string(b'ssh-rsa'))
            b'\x00\x00\x00\x07ssh-rsa'

        """
        try:
            ret = bytearray()
            ret.extend(cls.uint32(len(payload)))
            ret.extend(payload)
            return ret
        except Exception as e:
            raise TypeError('invalid payload type') from e

    @classmethod
    def unstring(cls, bytestring: bytes | bytearray, /) -> bytes | bytearray:
        r"""Unpack an SSH string.

        Args:
            bytestring: A framed byte string.

        Returns:
            The unframed byte string, i.e., the payload.

        Raises:
            ValueError:
                The byte string is not an SSH string.

        Examples:
            >>> bytes(SSHAgentClient.unstring(b'\x00\x00\x00\x07ssh-rsa'))
            b'ssh-rsa'
            >>> bytes(SSHAgentClient.unstring(SSHAgentClient.string(b'ssh-ed25519')))
            b'ssh-ed25519'

        """
        n = len(bytestring)
        if n < 4:
            raise ValueError('malformed SSH byte string')
        elif n != 4 + int.from_bytes(bytestring[:4], 'big', signed=False):
            raise ValueError('malformed SSH byte string')
        return bytestring[4:]

    @classmethod
    def unstring_prefix(
        cls, bytestring: bytes | bytearray, /
    ) -> tuple[bytes | bytearray, bytes | bytearray]:
        r"""Unpack an SSH string at the beginning of the byte string.

        Args:
            bytestring:
                A (general) byte string, beginning with a framed/SSH
                byte string.

        Returns:
            A 2-tuple `(a, b)`, where `a` is the unframed byte
            string/payload at the beginning of input byte string, and
            `b` is the remainder of the input byte string.

        Raises:
            ValueError:
                The byte string does not begin with an SSH string.

        Examples:
            >>> a, b = SSHAgentClient.unstring_prefix(
            ...     b'\x00\x00\x00\x07ssh-rsa____trailing data')
            >>> (bytes(a), bytes(b))
            (b'ssh-rsa', b'____trailing data')
            >>> a, b = SSHAgentClient.unstring_prefix(
            ...     SSHAgentClient.string(b'ssh-ed25519'))
            >>> (bytes(a), bytes(b))
            (b'ssh-ed25519', b'')

        """
        n = len(bytestring)
        if n < 4:
            raise ValueError('malformed SSH byte string')
        m = int.from_bytes(bytestring[:4], 'big', signed=False)
        if m + 4 > n:
            raise ValueError('malformed SSH byte string')
        return (bytestring[4:m + 4], bytestring[m + 4:])

    def request(
        self, code: int, payload: bytes | bytearray, /
    ) -> tuple[int, bytes | bytearray]:
        """Issue a generic request to the SSH agent.

        Args:
            code:
                The request code.  See the SSH agent protocol for
                protocol numbers to use here (and which protocol numbers
                to expect in a response).
            payload:
                A byte string containing the payload, or "contents", of
                the request.  Request-specific.  `request` will add any
                necessary wire framing around the request code and the
                payload.

        Returns:
            A 2-tuple consisting of the response code and the payload,
            with all wire framing removed.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.

        """
        request_message = bytearray([code])
        request_message.extend(payload)
        self._connection.sendall(self.string(request_message))
        chunk = self._connection.recv(4)
        if len(chunk) < 4:
            raise EOFError('cannot read response length')
        response_length = int.from_bytes(chunk, 'big', signed=False)
        response = self._connection.recv(response_length)
        if len(response) < response_length:
            raise EOFError('truncated response from SSH agent')
        return response[0], response[1:]

    def list_keys(self) -> Sequence[KeyCommentPair]:
        """Request a list of keys known to the SSH agent.

        Returns:
            A read-only sequence of key/comment pairs.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            TrailingDataError:
                The response from the SSH agent is too long.
            RuntimeError:
                The agent failed to complete the request.

        """
        response_code, response = self.request(
            SSH_AGENTC.REQUEST_IDENTITIES.value, b'')
        if response_code != SSH_AGENT.IDENTITIES_ANSWER.value:
            raise RuntimeError(
                f'error return from SSH agent: '
                f'{response_code = }, {response = }'
            )
        response_stream = collections.deque(response)
        def shift(num: int) -> bytes:
            buf = collections.deque(bytes())
            for i in range(num):
                try:
                    val = response_stream.popleft()
                except IndexError:
                    response_stream.extendleft(reversed(buf))
                    raise EOFError(
                        'truncated response from SSH agent'
                    ) from None
                buf.append(val)
            return bytes(buf)
        key_count = int.from_bytes(shift(4), 'big')
        keys: collections.deque[KeyCommentPair] = collections.deque()
        for i in range(key_count):
            key_size = int.from_bytes(shift(4), 'big')
            key = shift(key_size)
            comment_size = int.from_bytes(shift(4), 'big')
            comment = shift(comment_size)
            # Both `key` and `comment` are not wrapped as SSH strings.
            keys.append(KeyCommentPair(key, comment))
        if response_stream:
            raise TrailingDataError('overlong response from SSH agent')
        return keys

    def sign(
        self, /, key: bytes | bytearray, payload: bytes | bytearray,
        *, flags: int = 0, check_if_key_loaded: bool = False,
    ) -> bytes | bytearray:
        """Request the SSH agent sign the payload with the key.

        Args:
            key:
                The public SSH key to sign the payload with, in the same
                format as returned by, e.g., the `list_keys` method.
                The corresponding private key must have previously been
                loaded into the agent to successfully issue a signature.
            payload:
                A byte string of data to sign.
            flags:
                Optional flags for the signing request.  Currently
                passed on as-is to the agent.  In real-world usage, this
                could be used, e.g., to request more modern hash
                algorithms when signing with RSA keys.  (No such
                real-world usage is currently implemented.)
            check_if_key_loaded:
                If true, check beforehand (via `list_keys`) if the
                corresponding key has been loaded into the agent.

        Returns:
            The binary signature of the payload under the given key.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            TrailingDataError:
                The response from the SSH agent is too long.
            RuntimeError:
                The agent failed to complete the request.
            RuntimeError:
                `check_if_key_loaded` is true, and the `key` was not
                loaded into the agent.

        """
        if check_if_key_loaded:
            loaded_keys = frozenset({pair.key for pair in self.list_keys()})
            if bytes(key) not in loaded_keys:
                raise RuntimeError('target SSH key not loaded into agent')
        request_data = bytearray(self.string(key))
        request_data.extend(self.string(payload))
        request_data.extend(self.uint32(flags))
        response_code, response = self.request(
            SSH_AGENTC.SIGN_REQUEST.value, request_data)
        if response_code != SSH_AGENT.SIGN_RESPONSE.value:
            raise RuntimeError(
                f'signing data failed: {response_code = }, {response = }'
            )
        return self.unstring(response)
