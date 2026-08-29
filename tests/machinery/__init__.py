# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Testing machinery for `derivepassphrase`.

This is all the standalone, non-test-system-specific machinery used to
test `derivepassphrase`; this includes global settings, external API
wrappers, stub systems, and the like.

"""

from __future__ import annotations

import collections
import contextlib
import errno
import logging
import os
import re
import sys
from typing import TYPE_CHECKING, TypedDict

import click.testing
from typing_extensions import NamedTuple

from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase.ssh_agent import socketprovider
from tests import data

__all__ = ()

if TYPE_CHECKING:
    import types
    from collections.abc import (
        Callable,
        Generator,
        Iterable,
        Mapping,
        Sequence,
    )
    from contextlib import AbstractContextManager
    from typing import IO, Literal, NotRequired

    from typing_extensions import Any, Buffer, Self


# Test suite settings
# ===================

MIN_CONCURRENCY = 4
"""
The minimum amount of concurrent threads used for testing.
"""


def get_concurrency_limit() -> int:
    """Return the imposed limit on the number of concurrent threads.

    We use [`os.process_cpu_count`][] as the limit on Python 3.13 and
    higher, and [`os.cpu_count`][] on Python 3.12 and below.  On
    Python 3.12 and below, we explicitly support the `PYTHON_CPU_COUNT`
    environment variable.  We guarantee at least [`MIN_CONCURRENCY`][]
    many threads in any case.

    """  # noqa: RUF002
    result: int | None = None
    if sys.version_info >= (3, 13):
        result = os.process_cpu_count()
    else:
        with contextlib.suppress(KeyError, ValueError):
            result = result or int(os.environ["PYTHON_CPU_COUNT"], 10)
        with contextlib.suppress(AttributeError):
            result = result or len(os.sched_getaffinity(os.getpid()))
    return max(result if result is not None else 0, MIN_CONCURRENCY)


# Log/Error message searching
# ===========================


def message_emitted_factory(
    level: int,
    *,
    logger_name: str = cli.PROG_NAME,
) -> Callable[[str | re.Pattern[str], Sequence[tuple[str, int, str]]], bool]:
    """Return a function to test if a matching message was emitted.

    Args:
        level: The level to match messages at.
        logger_name: The name of the logger to match against.

    """

    def message_emitted(
        text: str | re.Pattern[str],
        record_tuples: Sequence[tuple[str, int, str]],
    ) -> bool:
        """Return true if a matching message was emitted.

        Args:
            text: Substring or pattern to match against.
            record_tuples: Items to match.

        """

        def check_record(record: tuple[str, int, str]) -> bool:
            if record[:2] != (logger_name, level):
                return False
            if isinstance(text, str):
                return text in record[2]
            return text.match(record[2]) is not None  # pragma: no cover

        return any(map(check_record, record_tuples))

    return message_emitted


# No need to assert debug messages as of yet.
info_emitted = message_emitted_factory(logging.INFO)
warning_emitted = message_emitted_factory(logging.WARNING)
deprecation_warning_emitted = message_emitted_factory(
    logging.WARNING, logger_name=f"{cli.PROG_NAME}.deprecation"
)
deprecation_info_emitted = message_emitted_factory(
    logging.INFO, logger_name=f"{cli.PROG_NAME}.deprecation"
)
error_emitted = message_emitted_factory(logging.ERROR)


# click.testing.CliRunner handling
# ================================


class ReadableResult(NamedTuple):
    """Helper class for formatting and testing click.testing.Result objects."""

    exception: BaseException | None
    exit_code: int
    stdout: str
    stderr: str

    def clean_exit(
        self, *, output: str = "", empty_stderr: bool = False
    ) -> bool:
        """Return whether the invocation exited cleanly.

        Args:
            output:
                An expected output string.

        """
        return (
            (
                not self.exception
                or (
                    isinstance(self.exception, SystemExit)
                    and self.exit_code == 0
                )
            )
            and (not output or output in self.stdout)
            and (not empty_stderr or not self.stderr)
        )

    def error_exit(
        self,
        *,
        error: str | re.Pattern[str] | type[BaseException] = BaseException,
        record_tuples: Sequence[tuple[str, int, str]] = (),
    ) -> bool:
        """Return whether the invocation exited uncleanly.

        Args:
            error:
                An expected error message, or an expected numeric error
                code, or an expected exception type.

        """

        def error_match(error: str | re.Pattern[str], line: str) -> bool:
            return (
                error in line
                if isinstance(error, str)
                else error.match(line) is not None
            )

        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if isinstance(error, type):
            return isinstance(self.exception, error)
        else:  # noqa: RET505
            assert isinstance(error, (str, re.Pattern))
            return (
                isinstance(self.exception, SystemExit)
                and self.exit_code > 0
                and (
                    not error
                    or any(
                        error_match(error, line)
                        for line in self.stderr.splitlines(True)
                    )
                    or error_emitted(error, record_tuples)
                )
            )


class CliRunner:
    """An abstracted CLI runner class.

    Intended to provide similar functionality and scope as the
    [`click.testing.CliRunner`][] class, though not necessarily
    `click`-specific.  Also allows for seamless migration away from
    `click`, if/when we decide this.

    """

    _SUPPORTS_MIX_STDERR_ATTRIBUTE = not hasattr(click.testing, "StreamMixer")
    """
    True if and only if [`click.testing.CliRunner`][] supports the
    `mix_stderr` attribute.  It was removed in 8.2.0 in favor of the
    `click.testing.StreamMixer` class.

    See also
    [`pallets/click#2523`](https://github.com/pallets/click/pull/2523).
    """

    def __init__(
        self,
        *,
        mix_stderr: bool = False,
        color: bool | None = None,
    ) -> None:
        self.color = color
        self.mix_stderr = mix_stderr

        class MixStderrAttribute(TypedDict):
            mix_stderr: NotRequired[bool]

        mix_stderr_args: MixStderrAttribute = (
            {"mix_stderr": mix_stderr}
            if self._SUPPORTS_MIX_STDERR_ATTRIBUTE
            else {}
        )
        # The "mix_stderr" argument, mandatory for our use case, was
        # removed in click 8.2.0 without a transition period.  Since we
        # cannot branch on the click version available to the type
        # checker, we disable static type checking for this call in
        # particular; our test suite will have to uncover any breakage
        # dynamically instead.
        self.click_testing_clirunner = click.testing.CliRunner(
            **mix_stderr_args  # type: ignore[misc]
        )

    def invoke(
        self,
        # The click.BaseCommand abstract base class, previously the base
        # class of click.Command and click.Group, was removed in click
        # 8.2.0 without a transition period, and click.Command instated
        # as the common base class instead.  To keep some degree of
        # compatibility with both old click and new click, we explicitly
        # list the (somewhat) concrete base classes we actually care
        # about here.
        cli: click.Command | click.Group,
        args: Sequence[str] | str | None = None,
        input: str | bytes | IO[Any] | None = None,
        env: Mapping[str, str | None] | None = None,
        catch_exceptions: bool = True,
        color: bool | None = None,
        **extra: Any,
    ) -> ReadableResult:
        if color is None:  # pragma: no cover
            color = self.color if self.color is not None else False
        raw_result = self.click_testing_clirunner.invoke(
            cli,
            args=args,
            input=input,
            env=env,
            catch_exceptions=catch_exceptions,
            color=color,
            **extra,
        )
        # In 8.2.0, r.stdout is no longer a property aliasing the
        # `output` attribute, but rather the raw stdout value.
        try:
            stderr = raw_result.stderr
        except ValueError:
            stderr = raw_result.stdout
        return ReadableResult(
            raw_result.exception,
            raw_result.exit_code,
            (raw_result.stdout if not self.mix_stderr else raw_result.output)
            or "",
            stderr or "",
        )

    def isolated_filesystem(
        self,
        temp_dir: str | os.PathLike[str] | None = None,
    ) -> AbstractContextManager[str]:
        return self.click_testing_clirunner.isolated_filesystem(
            temp_dir=temp_dir
        )


# Stubbed SSH agent request/response queue
# ========================================


class AgentProtocolResponseQueue:
    """A response queue for the SSH agent protocol.

    This queue wraps a map of request messages
    ([`AgentProtocolRequest`][data.AgentProtocolRequest]) to multiple
    response messages
    ([`AgentProtocolResponse`][data.AgentProtocolResponse]).  Whenever
    [`_send_request_message`][] is called with a payload that matches
    a [`AgentProtocolRequest`][data.AgentProtocolRequest] from the map,
    the corresponding
    [`AgentProtocolResponse`][data.AgentProtocolResponse] objects are
    added to the queue, to be read by subsequent
    [`_get_response_pair`][] calls.  The [`_send_request_message`][] and
    [`_get_response_pair`][] methods are function- and
    interface-compatible with the internal methods of the same name in
    [`ssh_agent.SSHAgentClient`][].

    The queue is a context manager.  When entered or exited, it
    verifies that the queue is empty.

    Use this agent stub implementation if you are modelling well-formed
    requests and responses, without network errors or protocol framing
    errors.  For modelling the latter, see [`StubbedSSHAgentSocket`][].

    """

    def __init__(
        self,
        request_responses_mapping: Mapping[
            data.AgentProtocolRequest,
            Sequence[data.AgentProtocolResponse],
        ],
    ) -> None:
        self.responses_map = request_responses_mapping
        self.queue: collections.deque[data.AgentProtocolResponse] = (
            collections.deque()
        )

    def __bool__(self) -> bool:
        return bool(self.queue)

    def __enter__(self) -> Self:
        assert not self, (
            f"Agent I/O queue already has contents: {self.queue!r}"
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> Literal[False]:
        if (exc_type, exc_value, exc_tb) != (
            None,
            None,
            None,
        ):  # pragma: no cover [external]
            return False
        assert not self, f"Agent I/O queue still has contents: {self.queue!r}"
        return False

    def _send_request_message(
        self,
        request_code: int | _types.SSH_AGENTC,
        payload: bytes | bytearray,
    ) -> None:
        req = data.AgentProtocolRequest(request_code, bytes(payload))
        assert req in self.responses_map, (
            f"No prepared response for the request {req!r}"
        )
        self.queue.extend(self.responses_map[req])

    def _get_response_pair(
        self,
    ) -> tuple[int | _types.SSH_AGENT, bytes | bytearray]:
        assert self.queue, "No more responses left to replay"
        response = self.queue.popleft()
        return response.code, response.payload


# Stubbed SSH agent socket
# ========================

# Base variant
# ------------


@socketprovider.SocketProvider.register(
    _types.BuiltinSSHAgentSocketProvider.STUB_AGENT
)
class StubbedSSHAgentSocket:
    """A stubbed SSH agent presenting an [`_types.SSHAgentSocket`][].

    On the network protocol side, the agent implements the full
    [`_types.SSHAgentSocket`][] interface, including pipelined and
    unaligned agent requests.  However, on the application side, the
    agent is intrinsically tied to [the set of SSH test
    keys][data.ALL_KEYS], and only gives meaningful answers for
    operations on the test keys and for agent operations in use by
    [`ssh_agent.SSHAgentClient`][].  The agent does not actually
    implement any cryptography; all cryptography-related answers are
    derived from the recorded test key data.

    It is not safe to further monkeypatch the agent's [`recv`][] or
    [`sendall`][] methods on their own: either monkeypatch both of them,
    or manipulate the [`send_to_client`][] bytes queue directly instead.
    Given an [`ssh_agent.SSHAgentClient`][] connected to
    a [`StubbedSSHAgentSocket`][], if the test ensures proper message
    serialization and protocol framing and if the monkeypatching can be
    expressed in terms of full request messages and full response
    messages, prefer using a [`AgentProtocolResponseQueue`][] to
    monkeypatch the client's high-level request/response-loop instead of
    monkeypatching the low-level socket communication in this agent
    socket.

    """

    _NO_FLAG_SUPPORT = "This stubbed SSH agent socket does not support flags."
    _PROTOCOL_VIOLATION = "SSH agent protocol violation."
    _INVALID_REQUEST = "Invalid request."
    _UNSUPPORTED_REQUEST = "Unsupported request."
    _INCOMPLETE_REQUEST = "The last request was incomplete."

    HEADER_SIZE = 4
    CODE_SIZE = 1

    KNOWN_EXTENSIONS = frozenset({
        "query",
        "list-extended@putty.projects.tartarus.org",
    })
    """Known and implemented protocol extensions."""

    def __init__(self, *extensions: str) -> None:
        """Initialize the agent."""
        self.send_to_client = bytearray()
        """
        The buffered response to the client, read piecemeal by [`recv`][].
        """
        self.receive_from_client = bytearray()
        """The last request issued by the client."""
        self.closed = False
        """True if the connection is closed, false otherwise."""
        self.enabled_extensions = frozenset(extensions) & self.KNOWN_EXTENSIONS
        """
        Extensions actually enabled in this particular stubbed SSH agent.
        """
        self.try_rfc6979 = False
        """
        Attempt to issue DSA and ECDSA signatures according to RFC 6979?
        """
        self.try_pageant_068_080 = False
        """
        Attempt to issue DSA and ECDSA signatures as per Pageant 0.68–0.80?
        """  # noqa: RUF001

    def __enter__(self) -> Self:
        """Return self."""
        return self

    def __exit__(self, *args: object) -> None:
        """Mark the agent's socket as closed.

        Raises:
            AssertionError:
                The last request to the agent was incomplete.

        """
        self.closed = True
        assert not self.receive_from_client, self._INCOMPLETE_REQUEST

    def sendall(self, data: Buffer, flags: int = 0, /) -> None:
        """Send data to the SSH agent.

        The signature, and behavior, is identical to
        [`socket.socket.sendall`][].  Upon successful sending, this
        agent will parse the request, call the appropriate handler, and
        buffer the result such that it can be read via [`recv`][], in
        accordance with the SSH agent protocol.

        Args:
            data: Binary data to send to the agent.
            flags: Reserved.  Must be 0.

        Returns:
            Nothing.  The result should be requested via [`recv`][], and
            interpreted in accordance with the SSH agent protocol.

        Raises:
            AssertionError:
                The flags argument, if specified, must be 0.
            OSError:
                The socket connection is already closed.

        """
        assert not flags, self._NO_FLAG_SUPPORT
        self._check_for_io_on_closed_connection()
        self.receive_from_client.extend(memoryview(data))
        while self.receive_from_client:
            result: Buffer | Iterable[int]
            if len(self.receive_from_client) < self.HEADER_SIZE:
                break
            count = int.from_bytes(
                self.receive_from_client[: self.HEADER_SIZE],
                "big",
                signed=False,
            )
            if count:
                code = int.from_bytes(
                    self.receive_from_client[
                        self.HEADER_SIZE : self.HEADER_SIZE + self.CODE_SIZE
                    ],
                    "big",
                    signed=False,
                )
                request = bytes(
                    self.receive_from_client[: self.HEADER_SIZE + count]
                )
                if len(request) < self.HEADER_SIZE + count:
                    break
                request_payload = request[self.HEADER_SIZE + self.CODE_SIZE :]

                if code == _types.SSH_AGENTC.REQUEST_IDENTITIES:
                    result = self.request_identities(list_extended=False)
                elif code == _types.SSH_AGENTC.SIGN_REQUEST:
                    result = self.sign(request_payload)
                elif self._check_for_extension(code, "query"):
                    result = self.query_extensions()
                elif self._check_for_extension(
                    code, "list-extended@putty.projects.tartarus.org"
                ):
                    result = self.request_identities(list_extended=True)
                else:
                    result = self._failure()
            else:
                request = bytes(self.receive_from_client[: self.HEADER_SIZE])
                result = self._failure()
            self.send_to_client.extend(
                ssh_agent.SSHAgentClient.string(bytes(result))
            )
            self.receive_from_client[: len(request)] = b""

    def recv(self, count: int, flags: int = 0, /) -> bytes:
        """Read data from the SSH agent.

        As per the SSH agent protocol, data is only available to be read
        immediately after a request via [`sendall`][] and if the socket
        connection is still open.  Calls to [`recv`][] at other points
        in time that attempt to read data violate the protocol, and will
        fail.  (A [`recv`][] of zero bytes does not read data.)  Calls
        to [`recv`][] when the socket connection is closed always fail.

        Args:
            count:
                Number of bytes to read from the agent.
            flags:
                Reserved.  Must be 0.

        Returns:
            (A chunk of) the SSH agent's response to the most recent
            request.  If reading 0 bytes, the returned chunk is always
            an empty byte string.

        Raises:
            AssertionError:
                The flags argument, if specified, must be 0.

                Alternatively, `recv` was called when there was no
                response to be obtained, in violation of the SSH agent
                protocol.
            OSError:
                The socket connection is already closed.

        """
        assert not flags, self._NO_FLAG_SUPPORT
        self._check_for_io_on_closed_connection()
        assert not count or self.send_to_client, self._PROTOCOL_VIOLATION
        ret = bytes(self.send_to_client[:count])
        del self.send_to_client[:count]
        return ret

    def _failure(self) -> bytes:
        return bytes(_types.SSH_AGENT.FAILURE)

    def _check_for_io_on_closed_connection(self) -> None:
        if self.closed:
            raise OSError(errno.EBADF, os.strerror(errno.EBADF))

    def _check_for_extension(self, code: int, extension: str) -> bool:
        if (
            extension not in self.enabled_extensions
            or code != _types.SSH_AGENTC.EXTENSION
        ):
            return False
        string = ssh_agent.SSHAgentClient.string
        extension_marker = b"\x1b" + string(extension.encode("ascii"))
        return self.receive_from_client.startswith(extension_marker, 4)

    def query_extensions(self) -> Generator[int, None, None]:
        """Answer an `SSH_AGENTC_EXTENSION` request.

        Yields:
            The bytes payload of the response, without the protocol
            framing.  The payload is yielded byte by byte, as an
            iterable of 8-bit integers.

        """
        yield _types.SSH_AGENT.EXTENSION_RESPONSE
        yield from ssh_agent.SSHAgentClient.string(b"query")
        extension_answers = [
            b"query",
            b"list-extended@putty.projects.tartarus.org",
        ]
        for a in extension_answers:
            yield from ssh_agent.SSHAgentClient.string(a)

    def request_identities(
        self, *, list_extended: bool = False
    ) -> Generator[int, None, None]:
        """Answer an `SSH_AGENTC_REQUEST_IDENTITIES` request.

        Args:
            list_extended:
                If true, answer an `SSH_AGENTC_EXTENSION` request for
                the `list-extended@putty.projects.tartarus.org`
                extension. Otherwise, answer an
                `SSH_AGENTC_REQUEST_IDENTITIES` request.

        Yields:
            The bytes payload of the response, without the protocol
            framing.  The payload is yielded byte by byte, as an
            iterable of 8-bit integers.

        """
        if list_extended:
            yield _types.SSH_AGENT.SUCCESS
        else:
            yield _types.SSH_AGENT.IDENTITIES_ANSWER
        signature_classes = [
            data.SSHTestKeyDeterministicSignatureClass.SPEC,
        ]
        if (
            "list-extended@putty.projects.tartarus.org"
            in self.enabled_extensions
        ):
            signature_classes.append(
                data.SSHTestKeyDeterministicSignatureClass.RFC_6979
            )
        keys = [
            v
            for v in data.ALL_KEYS.values()
            if any(cls in v.expected_signatures for cls in signature_classes)
        ]
        yield from ssh_agent.SSHAgentClient.uint32(len(keys))
        for key in keys:
            yield from ssh_agent.SSHAgentClient.string(key.public_key_data)
            yield from ssh_agent.SSHAgentClient.string(
                b"test key without passphrase"
            )
            if list_extended:
                yield from ssh_agent.SSHAgentClient.string(
                    ssh_agent.SSHAgentClient.uint32(0)
                )

    def sign(self, request_payload: bytes, /) -> bytes:
        """Answer an `SSH_AGENTC_SIGN_REQUEST` request.

        Args:
            request_payload:
                The data of the sign request, without the protocol
                framing or the request code.

        Returns:
            The bytes payload of the response, without the protocol
            framing.

        """
        try_rfc6979 = (
            "list-extended@putty.projects.tartarus.org"
            in self.enabled_extensions
        )
        spec = data.SSHTestKeyDeterministicSignatureClass.SPEC
        rfc6979 = data.SSHTestKeyDeterministicSignatureClass.RFC_6979
        try:
            key_blob, rest = ssh_agent.SSHAgentClient.unstring_prefix(
                request_payload
            )
            sign_data, rest = ssh_agent.SSHAgentClient.unstring_prefix(rest)
        except ValueError:
            return self._failure()
        if len(rest) != 4:
            return self._failure()
        flags = int.from_bytes(rest, "big")
        if flags:
            return self._failure()
        if sign_data != vault.Vault.UUID:
            return self._failure()
        for key in data.ALL_KEYS.values():
            if key.public_key_data == key_blob:
                if spec in key.expected_signatures:
                    return int.to_bytes(
                        _types.SSH_AGENT.SIGN_RESPONSE, 1, "big"
                    ) + ssh_agent.SSHAgentClient.string(
                        key.expected_signatures[spec].signature
                    )
                if try_rfc6979 and rfc6979 in key.expected_signatures:
                    return int.to_bytes(
                        _types.SSH_AGENT.SIGN_RESPONSE, 1, "big"
                    ) + ssh_agent.SSHAgentClient.string(
                        key.expected_signatures[rfc6979].signature
                    )
                return self._failure()
        return self._failure()


# Standard variant
# ----------------


@socketprovider.SocketProvider.register(
    _types.BuiltinSSHAgentSocketProvider.STUB_AGENT_WITH_ADDRESS
)
class StubbedSSHAgentSocketWithAddress(StubbedSSHAgentSocket):
    """A [`StubbedSSHAgentSocket`][] requiring a specific address."""

    ADDRESS = "stub-ssh-agent:"
    """The correct address for connecting to this stubbed agent."""

    def __init__(self, *extensions: str) -> None:
        """Initialize the agent, based on `SSH_AUTH_SOCK`.

        Socket addresses of the form `stub-ssh-agent:<errno_value>` will
        raise an [`OSError`][] (or the respective subclass) with the
        specified [`errno`][] value.  For example,
        `stub-ssh-agent:EPERM` will raise a [`PermissionError`][].

        Raises:
            KeyError:
                The `SSH_AUTH_SOCK` environment variable is not set.
            OSError:
                The address in `SSH_AUTH_SOCK` is unsuited.

        """
        super().__init__(*extensions)
        try:
            orig_address = os.environ["SSH_AUTH_SOCK"]
        except KeyError as exc:
            msg = "SSH_AUTH_SOCK environment variable"
            raise KeyError(msg) from exc
        address = orig_address
        if not address.startswith(self.ADDRESS):
            address = self.ADDRESS + "ENOENT"
        errcode = address.removeprefix(self.ADDRESS)
        if errcode and not (
            errcode.startswith("E") and hasattr(errno, errcode)
        ):
            errcode = "EINVAL"
        if errcode:
            errno_val = getattr(errno, errcode)
            raise OSError(errno_val, os.strerror(errno_val), orig_address)


# Deterministic variant
# ---------------------


@socketprovider.SocketProvider.register(
    _types.BuiltinSSHAgentSocketProvider.STUB_AGENT_WITH_ADDRESS_AND_DETERMINISTIC_DSA
)
class StubbedSSHAgentSocketWithAddressAndDeterministicDSA(
    StubbedSSHAgentSocketWithAddress
):
    """A [`StubbedSSHAgentSocketWithAddress`][] supporting deterministic DSA."""

    def __init__(self) -> None:
        """Initialize the agent.

        Set the supported extensions, and try issuing RFC 6979 and
        Pageant 0.68–0.80 DSA/ECDSA signatures, if possible.  See the
        [superclass constructor][StubbedSSHAgentSocketWithAddress] for
        other details.

        Raises:
            KeyError: See superclass.
            OSError: See superclass.

        """  # noqa: RUF002
        super().__init__("query", "list-extended@putty.projects.tartarus.org")
        self.try_rfc6979 = True
        self.try_pageant_068_080 = True
