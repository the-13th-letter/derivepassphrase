# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""A bare-bones SSH agent client supporting signing and key listing."""

from __future__ import annotations

import collections
import contextlib
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, ClassVar, overload

from typing_extensions import Never, Self, assert_type

from derivepassphrase import _types

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from collections.abc import Set as AbstractSet
    from types import TracebackType

    from typing_extensions import Buffer

__all__ = ("SSHAgentClient",)

# In SSH bytestrings, the "length" of the byte string is stored as
# a 4-byte/32-bit unsigned integer at the beginning.
HEAD_LEN = 4

# Needed for handling OpenSSH bug 3967.  See
# _check_for_extra_success_response_after_query_extension_request.
_OPENSSH_AGENT_10_3_QUERY_EXTENSION_RESPONSE_PAYLOAD = bytes.fromhex("""
00 00 00 05 71 75 65 72 79
00 00 00 18 73 65 73 73 69 6f 6e 2d
62 69 6e 64 40 6f 70 65 6e 73 73 68 2e 63 6f 6d
""")


def _check_for_extra_empty_success_response_after_query_extension_request(
    client: SSHAgentClient, response_data: bytes | bytearray
) -> None:
    """Check for extra `SUCCESS` responses after a "query" extension request.

    OpenSSH's `ssh-agent` version 10.3 erroneously answers a "query"
    extension request with two response messages: the expected
    [`EXTENSION_RESPONSE`][_types.SSH_AGENT.EXTENSION_RESPONSE] or
    [`SUCCESS`][_types.SSH_AGENT.SUCCESS] message, and the unexpected
    extra `SUCCESS` message.  This causes a misalignment of the request
    and response messages if further requests are later issued to the
    agent.

    ([OpenSSH acknowledges this as Bug 3967][OPENSSH_BZ3967], and
    intends to fix this in version 10.4.)

    This callback is intended to run immediately after issuing a "query"
    extension request to the agent, and after reading its response.  If
    we detect the aforementioned OpenSSH behavior, then we re-align the
    request and response messages queue.  Otherwise, we do nothing.  In
    particular, it is safe to call us (at the aforementioned time) even
    on different SSH agents, or on versions of OpenSSH's agent that do
    not exhibit this bug.

    [OPENSSH_BZ3967]: https://bugzilla.mindrot.org/show_bug.cgi?id=3967

    Args:
        client:
            The client connected to the SSH agent that may or may not
            exhibit this OpenSSH behavior.  We assume that the client
            has just issued a "query" extension request, that the client
            has read and parsed the (first) response of the agent, that
            the response message was an `EXTENSION_RESPONSE` or
            a `SUCCESS` message, and that the response message (except
            for the response code) is exactly the contents of the
            `response_data` argument.
        response_data:
            The payload of the response message to a "query" extension
            request issued to the SSH agent immediately prior.

    """
    if response_data == _OPENSSH_AGENT_10_3_QUERY_EXTENSION_RESPONSE_PAYLOAD:
        # We cannot blindly read from the agent socket to check
        # for a possible extra SUCCESS response: that would
        # deadlock if the extra response is missing.  Instead,
        # we issue a second "query" request, and depending on
        # whether we next see the extra empty SUCCESS response or not,
        # we know whether to discard an additional two response
        # messages or not.
        #
        # (Principally any request that does *not* ellicit
        # a SUCCESS response and which does not modify the
        # agent's state would do for this.)
        response_code, response_data2 = client.request(
            _types.SSH_AGENTC.REQUEST_IDENTITIES, b"", response_code=None
        )
        if response_code == _types.SSH_AGENT.SUCCESS and not response_data2:
            response_code, response_data2 = client._get_response_pair()  # noqa: SLF001
        assert response_code == _types.SSH_AGENT.IDENTITIES_ANSWER, (
            "failed to re-synchronize with agent via REQUEST_IDENTITIES "
            'after "query" EXTENSION_REQUEST: want IDENTITIES_ANSWER, '
            f"got {response_code!r}, {response_data2!r}"
        )


class TrailingDataError(RuntimeError):
    """The result contained trailing data."""

    def __init__(
        self, raw: bytes | bytearray = b"", trailing: bytes | bytearray = b""
    ) -> None:
        super().__init__("Overlong response from SSH agent")
        self.raw = bytes(raw)
        self.trailing = bytes(trailing)

    def __str__(self) -> str:  # pragma: no cover [debug]
        if self.raw or self.trailing:
            return (
                f"Overlong response from SSH agent: "
                f"raw = {self.raw!r}, trailing = {self.trailing!r}"
            )
        return super().__str__()

    def __repr__(self) -> str:  # pragma: no cover [debug]
        """"""  # noqa: D419
        return (
            f"{self.__class__.__name__}"
            f"(raw={self.raw!r}, trailing={self.trailing!r})"
        )


class SSHAgentFailedError(RuntimeError):
    """The SSH agent failed to complete the requested operation."""

    def __str__(self) -> str:
        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if self.args == (  # pragma: no branch
            _types.SSH_AGENT.FAILURE,
            b"",
        ):
            return "The SSH agent failed to complete the request"
        elif self.args[1]:  # noqa: RET505  # pragma: no cover [failsafe]
            code = self.args[0]
            msg = self.args[1]
            return f"[Code {code:d}] {msg!r}"
        else:  # pragma: no cover [failsafe]
            return repr(self)

    def __repr__(self) -> str:  # pragma: no cover [debug]
        """"""  # noqa: D419
        return f"{self.__class__.__name__}{self.args!r}"


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

    _connection: _types.SSHAgentSocket
    SOCKET_PROVIDERS: ClassVar = ("native",)
    """
    The default list of SSH agent socket providers.
    """

    def __init__(  # noqa: C901, PLR0912
        self,
        /,
        *,
        socket: _types.SSHAgentSocket | Sequence[str] | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            socket:
                An optional socket-like object, already connected to the
                SSH agent, or a list of names of socket providers to try.
                If not given, we query platform-specific default
                addresses, if possible.

        Raises:
            derivepassphrase.ssh_agent.socketprovider.NoSuchProviderError:
                The list of socket provider names contained an invalid
                entry.
            KeyError:
                An expected configuration entry or an expected environment
                variable is missing.
            NotImplementedError:
                The named socket provider is not functional or not
                applicable to this `derivepassphrase` installation, e.g.
                because it is generally not implemented yet, or it requires
                a specific operating system, or specific system
                functionality that is not provided by all Python versions,
                or external packages that are unavailable on this
                installation.

                This error may be raised multiple times, as an exception
                group.
            OSError:
                There was an error setting up a socket connection to the
                agent.

        """  # noqa: DOC501
        import socket as _socket  # noqa: PLC0415

        from derivepassphrase.ssh_agent import socketprovider  # noqa: PLC0415

        # On POSIX, the predominant type of communication channel is the
        # UNIX domain socket, which in Python is represented as
        # a `socket.socket` object.  This is (as of January 2026)
        # unsupported on The Annoying OS: Only in Windows 10 (on some
        # later builds at least) did Microsoft ship a partial
        # implementation of named UNIX domain sockets in stream mode,
        # but because of the limited scope Python does not provide
        # bindings to this functionality.  (The Annoying OS has other
        # predominant communication channels, but these are not
        # represented as `socket.socket` objects.)
        #
        # Thus, for practical purposes, using a `socket.socket` object
        # to interface a running SSH agent is not a valid code path on
        # The Annoying OS.  The code path should therefore be marked as
        # such.
        #
        # https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
        # https://github.com/microsoft/WSL/issues/4240
        # https://github.com/python/cpython/issues/77589
        if isinstance(
            socket, _socket.socket
        ):  # pragma: unless posix no cover [external]
            self._connection = socket
            # Test whether the socket is connected.
            self._connection.getpeername()
        elif isinstance(socket, str):
            self._connection = socketprovider.SocketProvider.resolve(socket)()
        elif socket is None or isinstance(socket, Sequence):
            if not socket:
                socket = self.SOCKET_PROVIDERS
            assert isinstance(socket, Sequence)  # for the type checker
            excs: list[NotImplementedError] = []
            providers: list[_types.SSHAgentSocketProvider] = []
            for candidate in socket:
                try:
                    provider = socketprovider.SocketProvider.resolve(candidate)
                except NotImplementedError as exc:
                    excs.append(exc)
                    continue
                else:
                    providers.append(provider)
            for provider in providers:
                try:
                    self._connection = provider()
                except NotImplementedError as exc:
                    excs.append(exc)
                    continue
                else:
                    break
            else:
                msg = "No supported SSH agent socket provider found."
                raise (
                    ExceptionGroup(msg, excs)
                    if excs
                    else NotImplementedError(msg)
                )
        elif isinstance(socket, _types.SSHAgentSocket):
            self._connection = socket
        else:  # pragma: no cover [failsafe]
            assert_type(socket, Never)
            msg = f"invalid socket object: {socket!r}"
            raise TypeError(msg)

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
        return int.to_bytes(num, 4, "big", signed=False)

    @classmethod
    def string(cls, payload: Buffer, /) -> bytes:
        r"""Format the payload as an SSH string, as per the agent protocol.

        Args:
            payload: A bytes-like object.

        Returns:
            The payload, framed in the SSH agent wire protocol format,
            as a bytes object.

        Examples:
            >>> SSHAgentClient.string(b"ssh-rsa")
            b'\x00\x00\x00\x07ssh-rsa'

        """  # noqa: DOC501
        try:
            payload = memoryview(payload)
        except TypeError as e:
            msg = "invalid payload type"
            raise TypeError(msg) from e
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
            >>> SSHAgentClient.unstring(b"\x00\x00\x00\x07ssh-rsa")
            b'ssh-rsa'
            >>> SSHAgentClient.unstring(SSHAgentClient.string(b"ssh-ed25519"))
            b'ssh-ed25519'

        """
        bytestring = memoryview(bytestring)
        n = len(bytestring)
        msg = "malformed SSH byte string"
        if n < HEAD_LEN or n != HEAD_LEN + int.from_bytes(
            bytestring[:HEAD_LEN], "big", signed=False
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
            ...     b"\x00\x00\x00\x07ssh-rsa____trailing data"
            ... )
            (b'ssh-rsa', b'____trailing data')
            >>> SSHAgentClient.unstring_prefix(
            ...     SSHAgentClient.string(b"ssh-ed25519")
            ... )
            (b'ssh-ed25519', b'')

        """
        bytestring = memoryview(bytestring).toreadonly()
        n = len(bytestring)
        msg = "malformed SSH byte string"
        if n < HEAD_LEN:
            raise ValueError(msg)
        m = int.from_bytes(bytestring[:HEAD_LEN], "big", signed=False)
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
        conn: SSHAgentClient
        | _types.SSHAgentSocket
        | Sequence[str]
        | None = None,
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

                If `None`, or a list of names of socket providers, then
                construct a client according to those connection hints
                ("auto-discovery"), and enter a context within this
                client's scope.  After exiting the context, both the
                client and its socket are destroyed.

        Yields:
            When entering this context, return the SSH agent client.

        Raises:
            derivepassphrase.ssh_agent.socketprovider.NoSuchProviderError:
                As per [`__init__`][SSHAgentClient].
            KeyError:
                As per [`__init__`][SSHAgentClient], including the
                multiple raise as an exception group.
            NotImplementedError:
                As per [`__init__`][SSHAgentClient].
            OSError:
                As per [`__init__`][SSHAgentClient].

        """  # noqa: DOC501
        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if isinstance(conn, SSHAgentClient):
            with contextlib.nullcontext():
                yield conn
        elif (
            isinstance(conn, (_types.SSHAgentSocket, str, Sequence))
            or conn is None
        ):
            with SSHAgentClient(socket=conn) as client:
                yield client
        else:  # pragma: no cover [failsafe]
            assert_type(conn, Never)
            msg = f"invalid connection hint: {conn!r}"
            raise TypeError(msg)

    def _agent_is_pageant(self) -> bool:
        """Return True if we are connected to Pageant.

        Warning:
            This is a heuristic, not a verified query or computation.

        """
        return (
            b"list-extended@putty.projects.tartarus.org"
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
            "Pageant": self._agent_is_pageant,
        }
        return any(  # pragma: no branch
            v() for v in known_good_agents.values()
        )

    def _send_request_message(
        self, code: int | _types.SSH_AGENTC, payload: Buffer, /
    ) -> None:
        """Prepare and send a generic request to the SSH agent.

        We take care of packing, framing and sending the request.

        Args:
            code:
                See [request][].
            payload:
                See [request][].

        """
        payload = memoryview(payload)
        request_message = bytearray([code])
        request_message.extend(payload)
        self._connection.sendall(self.string(request_message))

    def _get_response_pair(self) -> tuple[int, bytes]:
        """Read the response for a generic request to the SSH agent.

        Returns:
            A 2-tuple consisting of the response code and the payload,
            with all wire framing removed.

        Raises:
            EOFError:
                The response from the SSH agent is truncated or missing.
            OSError:
                There was a communication error with the SSH agent.

        """
        chunk = self._connection.recv(HEAD_LEN)
        if len(chunk) < HEAD_LEN:
            msg = "cannot read response length"
            raise EOFError(msg)
        response_length = int.from_bytes(chunk, "big", signed=False)
        response = self._connection.recv(response_length)
        if len(response) < response_length:
            msg = "truncated response from SSH agent"
            raise EOFError(msg)
        return response[0], response[1:]

    @overload
    def request(
        self,
        code: int | _types.SSH_AGENTC,
        payload: Buffer,
        /,
        *,
        response_code: None = None,
    ) -> tuple[int, bytes]: ...

    @overload
    def request(
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
    def request(
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
        if isinstance(response_code, int):  # pragma: no branch
            response_code = frozenset({response_code})
        self._send_request_message(code, payload)
        actual_code, response = self._get_response_pair()
        if not response_code:  # pragma: no cover [failsafe]
            return actual_code, response
        if actual_code not in response_code:
            raise SSHAgentFailedError(actual_code, response)
        return response

    def list_keys(self) -> Sequence[_types.SSHKeyCommentPair]:
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
            b"",
            response_code=_types.SSH_AGENT.IDENTITIES_ANSWER,
        )
        response_stream = collections.deque(response)

        def shift(num: int) -> bytes:
            buf: collections.deque[int] = collections.deque()
            for _ in range(num):
                try:
                    val = response_stream.popleft()
                except IndexError:
                    response_stream.extendleft(reversed(buf))
                    msg = "truncated response from SSH agent"
                    raise EOFError(msg) from None
                buf.append(val)
            return bytes(buf)

        key_count = int.from_bytes(shift(4), "big")
        keys: collections.deque[_types.SSHKeyCommentPair]
        keys = collections.deque()
        for _ in range(key_count):
            key_size = int.from_bytes(shift(4), "big")
            key = shift(key_size)
            comment_size = int.from_bytes(shift(4), "big")
            comment = shift(comment_size)
            # Both `key` and `comment` are not wrapped as SSH strings.
            keys.append(_types.SSHKeyCommentPair(key, comment))
        if response_stream:
            raise TrailingDataError(
                raw=response, trailing=bytes(response_stream)
            )
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
                msg = "target SSH key not loaded into agent"
                raise KeyError(msg)
        request_data = bytearray(self.string(key))
        request_data.extend(self.string(payload))
        request_data.extend(self.uint32(flags))
        return bytes(
            self.unstring(
                self.request(
                    _types.SSH_AGENTC.SIGN_REQUEST,
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
            # The draft-miller-ssh-agent-14 (2024-04-15) version of the
            # SSH agent protocol specification introduced the
            # SSH_AGENT_EXTENSION_RESPONSE protocol message, and
            # suggested the use of this message in the response for
            # SSH_AGENTC_EXTENSION requests.  Older versions of the spec
            # used the SSH_AGENT_SUCCESS response, and even the newer
            # spec versions contain wording that allows such usage
            # across all SSH_AGENTC_EXTENSION requests.  Both response
            # codes are used in the wild (`ssh-agent`/OpenSSH 10.3,
            # `pageant`/PuTTY 0.83), so both of them need to be
            # supported for compatibility reasons.
            response_data = self.request(
                _types.SSH_AGENTC.EXTENSION,
                self.string(b"query"),
                response_code={
                    _types.SSH_AGENT.EXTENSION_RESPONSE,
                    _types.SSH_AGENT.SUCCESS,
                },
            )
            _check_for_extra_empty_success_response_after_query_extension_request(
                self, response_data
            )
        except SSHAgentFailedError:
            # Cannot query extension support.  Assume no extensions.
            # This isn't necessarily true, e.g. for OpenSSH's ssh-agent
            # 10.2 and older.
            return frozenset()
        extensions: set[bytes] = set()
        msg = "Malformed response from SSH agent"
        msg2 = "Extension response message does not match request"
        try:
            query, response_data = self.unstring_prefix(response_data)
        except ValueError as e:
            raise RuntimeError(msg) from e
        if bytes(query) != b"query":
            raise RuntimeError(msg2)
        while response_data:
            try:
                extension, response_data = self.unstring_prefix(response_data)
            except ValueError as e:
                raise RuntimeError(msg) from e
            else:
                extensions.add(bytes(extension))
        return frozenset(extensions)
