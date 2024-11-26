# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""A bare-bones SSH agent client supporting signing and key listing."""

from __future__ import annotations

import collections
import contextlib
import os
import socket
from typing import TYPE_CHECKING, overload

from typing_extensions import Self, assert_never

from derivepassphrase import _types

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence
    from collections.abc import Set as AbstractSet
    from types import TracebackType

    from typing_extensions import Buffer

__all__ = ('SSHAgentClient',)
__author__ = 'Marco Ricci <software@the13thletter.info>'

# In SSH bytestrings, the "length" of the byte string is stored as
# a 4-byte/32-bit unsigned integer at the beginning.
HEAD_LEN = 4

_socket = socket


class TrailingDataError(RuntimeError):
    """The result contained trailing data."""

    def __init__(self) -> None:
        super().__init__('Overlong response from SSH agent')


class SSHAgentFailedError(RuntimeError):
    """The SSH agent failed to complete the requested operation."""

    def __str__(self) -> str:
        # Use match/case here once Python 3.9 becomes unsupported.
        if self.args == (  # pragma: no branch
            _types.SSH_AGENT.FAILURE.value,
            b'',
        ):
            return 'The SSH agent failed to complete the request'
        elif self.args[1]:  # noqa: RET505  # pragma: no cover
            code = self.args[0]
            msg = self.args[1].decode('utf-8', 'surrogateescape')
            return f'[Code {code:d}] {msg:s}'
        else:  # pragma: no cover
            return repr(self)

    def __repr__(self) -> str:  # pragma: no cover
        return f'{self.__class__.__name__}{self.args!r}'


class SSHAgentClient:
    """A bare-bones SSH agent client supporting signing and key listing.

    The main use case is requesting the agent sign some data, after
    checking that the necessary key is already loaded.

    The main fleshed out methods are [`list_keys`][] and [`sign`][],
    which implement the [`REQUEST_IDENTITIES`]
    [_types.SSH_AGENTC.REQUEST_IDENTITIES] and [`SIGN_REQUEST`]
    [_types.SSH_AGENTC.SIGN_REQUEST] requests.  If you *really* wanted
    to, there is enough infrastructure in place to issue other requests
    as defined in the protocol---it's merely the wrapper functions and
    the protocol numbers table that are missing.

    """

    _connection: socket.socket

    def __init__(
        self, /, *, socket: socket.socket | None = None, timeout: int = 125
    ) -> None:
        """Initialize the client.

        Args:
            socket:
                An optional socket, already connected to the SSH agent.
                If not given, we query the `SSH_AUTH_SOCK` environment
                variable to auto-discover the correct socket address.

                [We currently only support connecting via UNIX domain
                sockets][issue13], and only on platforms with support
                for [`socket.AF_UNIX`][AF_UNIX].

                [issue13]: https://github.com/the-13th-letter/derivepassphrase/issues/13
                [AF_UNIX]: https://docs.python.org/3/library/socket.html#socket.AF_UNIX
            timeout:
                A connection timeout for the SSH agent.  Only used if
                the socket is not yet connected.  The default value
                gives ample time for agent connections forwarded via
                SSH on high-latency networks (e.g. Tor).

        Raises:
            KeyError:
                The `SSH_AUTH_SOCK` environment variable was not found.
            NotImplementedError:
                This Python version does not support UNIX domain
                sockets, necessary to automatically connect to a running
                SSH agent via the `SSH_AUTH_SOCK` environment variable.
            OSError:
                There was an error setting up a socket connection to the
                agent.

        """
        if socket is not None:
            self._connection = socket
            # Test whether the socket is connected.
            self._connection.getpeername()
        else:
            if not hasattr(_socket, 'AF_UNIX'):
                msg = (
                    'This Python version does not support UNIX domain sockets'
                )
                raise NotImplementedError(msg)
            self._connection = _socket.socket(family=_socket.AF_UNIX)
            if 'SSH_AUTH_SOCK' not in os.environ:
                msg = 'SSH_AUTH_SOCK environment variable'
                raise KeyError(msg)
            ssh_auth_sock = os.environ['SSH_AUTH_SOCK']
            self._connection.settimeout(timeout)
            self._connection.connect(ssh_auth_sock)

    def __enter__(self) -> Self:
        """Close socket connection upon context manager completion.

        Returns:
            Self.

        """
        self._connection.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool:
        """Close socket connection upon context manager completion.

        Args:
            exc_type: An optional exception type.
            exc_val: An optional exception value.
            exc_tb: An optional exception traceback.

        Returns:
            True if the exception was handled, false if it should
            propagate.

        """
        return bool(
            self._connection.__exit__(exc_type, exc_val, exc_tb)  # type: ignore[func-returns-value]
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
    def string(cls, payload: Buffer, /) -> bytes:
        r"""Format the payload as an SSH string, as per the agent protocol.

        Args:
            payload: A bytes-like object.

        Returns:
            The payload, framed in the SSH agent wire protocol format,
            as a bytes object.

        Examples:
            >>> SSHAgentClient.string(b'ssh-rsa')
            b'\x00\x00\x00\x07ssh-rsa'

        """
        try:
            payload = memoryview(payload)
        except TypeError as e:
            msg = 'invalid payload type'
            raise TypeError(msg) from e  # noqa: DOC501
        ret = bytearray()
        ret.extend(cls.uint32(len(payload)))
        ret.extend(payload)
        return bytes(ret)

    @classmethod
    def unstring(cls, bytestring: Buffer, /) -> bytes:
        r"""Unpack an SSH string.

        Args:
            bytestring: A framed bytes-like object.

        Returns:
            The payload, as a bytes object.

        Raises:
            ValueError:
                The byte string is not an SSH string.

        Examples:
            >>> SSHAgentClient.unstring(b'\x00\x00\x00\x07ssh-rsa')
            b'ssh-rsa'
            >>> SSHAgentClient.unstring(SSHAgentClient.string(b'ssh-ed25519'))
            b'ssh-ed25519'

        """
        bytestring = memoryview(bytestring)
        n = len(bytestring)
        msg = 'malformed SSH byte string'
        if n < HEAD_LEN or n != HEAD_LEN + int.from_bytes(
            bytestring[:HEAD_LEN], 'big', signed=False
        ):
            raise ValueError(msg)
        return bytes(bytestring[HEAD_LEN:])

    @classmethod
    def unstring_prefix(cls, bytestring: Buffer, /) -> tuple[bytes, bytes]:
        r"""Unpack an SSH string at the beginning of the byte string.

        Args:
            bytestring:
                A bytes-like object, beginning with a framed/SSH byte
                string.

        Returns:
            A 2-tuple `(a, b)`, where `a` is the unframed byte
            string/payload at the beginning of input byte string, and
            `b` is the remainder of the input byte string.

        Raises:
            ValueError:
                The byte string does not begin with an SSH string.

        Examples:
            >>> SSHAgentClient.unstring_prefix(
            ...     b'\x00\x00\x00\x07ssh-rsa____trailing data'
            ... )
            (b'ssh-rsa', b'____trailing data')
            >>> SSHAgentClient.unstring_prefix(
            ...     SSHAgentClient.string(b'ssh-ed25519')
            ... )
            (b'ssh-ed25519', b'')

        """
        bytestring = memoryview(bytestring).toreadonly()
        n = len(bytestring)
        msg = 'malformed SSH byte string'
        if n < HEAD_LEN:
            raise ValueError(msg)
        m = int.from_bytes(bytestring[:HEAD_LEN], 'big', signed=False)
        if m + HEAD_LEN > n:
            raise ValueError(msg)
        return (
            bytes(bytestring[HEAD_LEN : m + HEAD_LEN]),
            bytes(bytestring[m + HEAD_LEN :]),
        )

    @classmethod
    @contextlib.contextmanager
    def ensure_agent_subcontext(
        cls,
        conn: SSHAgentClient | socket.socket | None = None,
    ) -> Iterator[SSHAgentClient]:
        """Return an SSH agent client subcontext.

        If necessary, construct an SSH agent client first using the
        connection hint.

        Args:
            conn:
                If an existing SSH agent client, then enter a context
                within this client's scope.  After exiting the context,
                the client persists, including its socket.

                If a socket, then construct a client using this socket,
                then enter a context within this client's scope.  After
                exiting the context, the client is destroyed and the
                socket is closed.

                If `None`, construct a client using agent
                auto-discovery, then enter a context within this
                client's scope.  After exiting the context, both the
                client and its socket are destroyed.

        Yields:
            When entering this context, return the SSH agent client.

        Raises:
            KeyError:
                `conn` was `None`, and the `SSH_AUTH_SOCK` environment
                variable was not found.
            NotImplementedError:
                `conn` was `None`, and this Python does not support
                [`socket.AF_UNIX`][], so the SSH agent client cannot be
                automatically set up.
            OSError:
                `conn` was a socket or `None`, and there was an error
                setting up a socket connection to the agent.

        """
        # Use match/case here once Python 3.9 becomes unsupported.
        if isinstance(conn, SSHAgentClient):
            with contextlib.nullcontext():
                yield conn
        elif isinstance(conn, socket.socket) or conn is None:
            with SSHAgentClient(socket=conn) as client:
                yield client
        else:  # pragma: no cover
            assert_never(conn)
            msg = f'invalid connection hint: {conn!r}'
            raise TypeError(msg)  # noqa: DOC501

    def _agent_is_pageant(self) -> bool:
        """Return True if we are connected to Pageant.

        Warning:
            This is a heuristic, not a verified query or computation.

        """
        return (
            b'list-extended@putty.projects.tartarus.org'
            in self.query_extensions()
        )

    def has_deterministic_dsa_signatures(self) -> bool:
        """Check whether the agent returns deterministic DSA signatures.

        This includes ECDSA signatures.

        Generally, this means that the SSH agent implements [RFC 6979][]
        or a similar system.

        [RFC 6979]: https://www.rfc-editor.org/rfc/rfc6979

        Returns:
            True if a known agent was detected where signatures are
            deterministic for all DSA key types, false otherwise.

        Note: Known agents with deterministic signatures
            | agent           | detected via                                                  |
            |:----------------|:--------------------------------------------------------------|
            | Pageant (PuTTY) | `list-extended@putty.projects.tartarus.org` extension request |

        """  # noqa: E501
        known_good_agents = {
            'Pageant': self._agent_is_pageant,
        }
        return any(  # pragma: no branch
            v() for v in known_good_agents.values()
        )

    @overload
    def request(  # pragma: no cover
        self,
        code: int | _types.SSH_AGENTC,
        payload: Buffer,
        /,
        *,
        response_code: None = None,
    ) -> tuple[int, bytes]: ...

    @overload
    def request(  # pragma: no cover
        self,
        code: int | _types.SSH_AGENTC,
        payload: Buffer,
        /,
        *,
        response_code: Iterable[_types.SSH_AGENT | int] = frozenset({
            _types.SSH_AGENT.SUCCESS
        }),
    ) -> bytes: ...

    @overload
    def request(  # pragma: no cover
        self,
        code: int | _types.SSH_AGENTC,
        payload: Buffer,
        /,
        *,
        response_code: _types.SSH_AGENT | int = _types.SSH_AGENT.SUCCESS,
    ) -> bytes: ...

    def request(
        self,
        code: int | _types.SSH_AGENTC,
        payload: Buffer,
        /,
        *,
        response_code: (
            Iterable[_types.SSH_AGENT | int] | _types.SSH_AGENT | int | None
        ) = None,
    ) -> tuple[int, bytes] | bytes:
        """Issue a generic request to the SSH agent.

        Args:
            code:
                The request code.  See the SSH agent protocol for
                protocol numbers to use here (and which protocol numbers
                to expect in a response).
            payload:
                A bytes-like object containing the payload, or
                "contents", of the request.  Request-specific.

                It is our responsibility to add any necessary wire
                framing around the request code and the payload,
                not the caller's.
            response_code:
                An optional response code, or a set of response codes,
                that we expect.  If given, and the actual response code
                does not match, raise an error.

        Returns:
            A 2-tuple consisting of the response code and the payload,
            with all wire framing removed.

            If a response code was passed, then only return the payload.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            OSError:
                There was a communication error with the SSH agent.
            SSHAgentFailedError:
                We expected specific response codes, but did not receive
                any of them.

        """
        if isinstance(  # pragma: no branch
            response_code, (int, _types.SSH_AGENT)
        ):
            response_code = frozenset({response_code})
        if response_code is not None:  # pragma: no branch
            response_code = frozenset({
                c if isinstance(c, int) else c.value for c in response_code
            })
        payload = memoryview(payload)
        request_message = bytearray([
            code if isinstance(code, int) else code.value
        ])
        request_message.extend(payload)
        self._connection.sendall(self.string(request_message))
        chunk = self._connection.recv(HEAD_LEN)
        if len(chunk) < HEAD_LEN:
            msg = 'cannot read response length'
            raise EOFError(msg)
        response_length = int.from_bytes(chunk, 'big', signed=False)
        response = self._connection.recv(response_length)
        if len(response) < response_length:
            msg = 'truncated response from SSH agent'
            raise EOFError(msg)
        if not response_code:  # pragma: no cover
            return response[0], response[1:]
        if response[0] not in response_code:
            raise SSHAgentFailedError(response[0], response[1:])
        return response[1:]

    def list_keys(self) -> Sequence[_types.KeyCommentPair]:
        """Request a list of keys known to the SSH agent.

        Returns:
            A read-only sequence of key/comment pairs.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            OSError:
                There was a communication error with the SSH agent.
            TrailingDataError:
                The response from the SSH agent is too long.
            SSHAgentFailedError:
                The agent failed to complete the request.

        """
        response = self.request(
            _types.SSH_AGENTC.REQUEST_IDENTITIES.value,
            b'',
            response_code=_types.SSH_AGENT.IDENTITIES_ANSWER,
        )
        response_stream = collections.deque(response)

        def shift(num: int) -> bytes:
            buf = collections.deque(b'')
            for _ in range(num):
                try:
                    val = response_stream.popleft()
                except IndexError:
                    response_stream.extendleft(reversed(buf))
                    msg = 'truncated response from SSH agent'
                    raise EOFError(msg) from None
                buf.append(val)
            return bytes(buf)

        key_count = int.from_bytes(shift(4), 'big')
        keys: collections.deque[_types.KeyCommentPair]
        keys = collections.deque()
        for _ in range(key_count):
            key_size = int.from_bytes(shift(4), 'big')
            key = shift(key_size)
            comment_size = int.from_bytes(shift(4), 'big')
            comment = shift(comment_size)
            # Both `key` and `comment` are not wrapped as SSH strings.
            keys.append(_types.KeyCommentPair(key, comment))
        if response_stream:
            raise TrailingDataError
        return keys

    def sign(
        self,
        /,
        key: Buffer,
        payload: Buffer,
        *,
        flags: int = 0,
        check_if_key_loaded: bool = False,
    ) -> bytes:
        """Request the SSH agent sign the payload with the key.

        Args:
            key:
                The public SSH key to sign the payload with, in the same
                format as returned by, e.g., the [`list_keys`][] method.
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
                If true, check beforehand (via [`list_keys`][]) if the
                corresponding key has been loaded into the agent.

        Returns:
            The binary signature of the payload under the given key.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            OSError:
                There was a communication error with the SSH agent.
            TrailingDataError:
                The response from the SSH agent is too long.
            SSHAgentFailedError:
                The agent failed to complete the request.
            KeyError:
                `check_if_key_loaded` is true, and the `key` was not
                loaded into the agent.

        """
        key = memoryview(key)
        payload = memoryview(payload)
        if check_if_key_loaded:
            loaded_keys = frozenset({pair.key for pair in self.list_keys()})
            if bytes(key) not in loaded_keys:
                msg = 'target SSH key not loaded into agent'
                raise KeyError(msg)
        request_data = bytearray(self.string(key))
        request_data.extend(self.string(payload))
        request_data.extend(self.uint32(flags))
        return bytes(
            self.unstring(
                self.request(
                    _types.SSH_AGENTC.SIGN_REQUEST.value,
                    request_data,
                    response_code=_types.SSH_AGENT.SIGN_RESPONSE,
                )
            )
        )

    def query_extensions(self) -> AbstractSet[bytes]:
        """Request a listing of extensions supported by the SSH agent.

        Returns:
            A read-only set of extension names the SSH agent says it
            supports.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            OSError:
                There was a communication error with the SSH agent.
            RuntimeError:
                The response from the SSH agent is malformed.

        Note:
            The set of supported extensions is queried via the `query`
            extension request.  If the agent does not support the query
            extension request, or extension requests in general, then an
            empty set is returned.  This does not however imply that the
            agent doesn't support *any* extension request... merely that
            it doesn't support extension autodiscovery.

        """
        try:
            response_data = self.request(
                _types.SSH_AGENTC.EXTENSION,
                self.string(b'query'),
                response_code={
                    _types.SSH_AGENT.EXTENSION_RESPONSE,
                    _types.SSH_AGENT.SUCCESS,
                },
            )
        except SSHAgentFailedError:
            # Cannot query extension support.  Assume no extensions.
            # This isn't necessarily true, e.g. for OpenSSH's ssh-agent.
            return frozenset()
        extensions: set[bytes] = set()
        msg = 'Malformed response from SSH agent'
        msg2 = 'Extension response message does not match request'
        try:
            _query, response_data = self.unstring_prefix(response_data)
        except ValueError as e:
            raise RuntimeError(msg) from e
        if bytes(_query) != b'query':
            raise RuntimeError(msg2)
        while response_data:
            try:
                extension, response_data = self.unstring_prefix(response_data)
            except ValueError as e:
                raise RuntimeError(msg) from e
            else:
                extensions.add(bytes(extension))
        return frozenset(extensions)
