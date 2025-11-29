# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import contextlib
import errno
import logging
import os
import re
import sys
from typing import TYPE_CHECKING, TypedDict

import click.testing
from typing_extensions import NamedTuple

import tests.data
from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase.ssh_agent import socketprovider

__all__ = ()

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from contextlib import AbstractContextManager
    from typing import IO, NotRequired

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
                    or tests.machinery.error_emitted(error, record_tuples)
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
        self.click_testing_clirunner = click.testing.CliRunner(  # type: ignore[misc]
            **mix_stderr_args
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
        return ReadableResult.parse(raw_result)

    def isolated_filesystem(
        self,
        temp_dir: str | os.PathLike[str] | None = None,
    ) -> AbstractContextManager[str]:
        return self.click_testing_clirunner.isolated_filesystem(
            temp_dir=temp_dir
        )


# Stubbed SSH agent socket
# ========================

# Base variant
# ------------


@socketprovider.SocketProvider.register("stub_agent")
class StubbedSSHAgentSocket:
    """A stubbed SSH agent presenting an [`_types.SSHAgentSocket`][]."""

    _SOCKET_IS_CLOSED = "Socket is closed."
    _NO_FLAG_SUPPORT = "This stubbed SSH agent socket does not support flags."
    _PROTOCOL_VIOLATION = "SSH agent protocol violation."
    _INVALID_REQUEST = "Invalid request."
    _UNSUPPORTED_REQUEST = "Unsupported request."

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
        """Mark the agent's socket as closed."""
        self.closed = True

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
            ValueError:
                The agent's socket is already closed.  No further
                requests can be sent.

        """
        assert not flags, self._NO_FLAG_SUPPORT
        if self.closed:
            raise ValueError(self._SOCKET_IS_CLOSED)
        self.receive_from_client.extend(memoryview(data))
        try:
            self.parse_client_request_and_dispatch()
        except ValueError:
            payload = int.to_bytes(_types.SSH_AGENT.FAILURE.value, 1, "big")
            self.send_to_client.extend(int.to_bytes(len(payload), 4, "big"))
            self.send_to_client.extend(payload)
        finally:
            self.receive_from_client.clear()

    def recv(self, count: int, flags: int = 0, /) -> bytes:
        """Read data from the SSH agent.

        As per the SSH agent protocol, data is only available to be read
        immediately after a request via [`sendall`][].  Calls to
        [`recv`][] at other points in time that attempt to read data
        violate the protocol, and will fail.  Notwithstanding the last
        sentence, at any point in time, though pointless, it is
        additionally permissible to read 0 bytes from the agent, or any
        number of bytes from a closed socket.

        Args:
            count:
                Number of bytes to read from the agent.
            flags:
                Reserved.  Must be 0.

        Returns:
            (A chunk of) the SSH agent's response to the most recent
            request.  If reading 0 bytes, or if reading from a closed
            socket, the returned chunk is always an empty byte string.

        Raises:
            AssertionError:
                The flags argument, if specified, must be 0.

                Alternatively, `recv` was called when there was no
                response to be obtained, in violation of the SSH agent
                protocol.

        """
        assert not flags, self._NO_FLAG_SUPPORT
        assert not count or self.closed or self.send_to_client, (
            self._PROTOCOL_VIOLATION
        )
        ret = bytes(self.send_to_client[:count])
        del self.send_to_client[:count]
        return ret

    def parse_client_request_and_dispatch(self) -> None:
        """Parse the client request and call the matching handler.

        This agent supports the
        [`SSH_AGENTC_REQUEST_IDENTITIES`][_types.SSH_AGENTC.REQUEST_IDENTITIES],
        [`SSH_AGENTC_SIGN_REQUEST`][_types.SSH_AGENTC.SIGN_REQUEST] and
        the [`SSH_AGENTC_EXTENSION`][_types.SSH_AGENTC.EXTENSION]
        request types.

        """

        if len(self.receive_from_client) < self.HEADER_SIZE + self.CODE_SIZE:
            raise ValueError(self._INVALID_REQUEST)
        target_header = ssh_agent.SSHAgentClient.uint32(
            len(self.receive_from_client) - self.HEADER_SIZE
        )
        if target_header != self.receive_from_client[: self.HEADER_SIZE]:
            raise ValueError(self._INVALID_REQUEST)
        code = _types.SSH_AGENTC(
            int.from_bytes(
                self.receive_from_client[
                    self.HEADER_SIZE : self.HEADER_SIZE + self.CODE_SIZE
                ],
                "big",
            )
        )

        def is_enabled_extension(extension: str) -> bool:
            if (
                extension not in self.enabled_extensions
                or code != _types.SSH_AGENTC.EXTENSION
            ):
                return False
            string = ssh_agent.SSHAgentClient.string
            extension_marker = b"\x1b" + string(extension.encode("ascii"))
            return self.receive_from_client.startswith(extension_marker, 4)

        result: Buffer | Iterator[int]
        if code == _types.SSH_AGENTC.REQUEST_IDENTITIES:
            result = self.request_identities(list_extended=False)
        elif code == _types.SSH_AGENTC.SIGN_REQUEST:
            result = self.sign()
        elif is_enabled_extension("query"):
            result = self.query_extensions()
        elif is_enabled_extension("list-extended@putty.projects.tartarus.org"):
            result = self.request_identities(list_extended=True)
        else:
            raise ValueError(self._UNSUPPORTED_REQUEST)
        self.send_to_client.extend(
            ssh_agent.SSHAgentClient.string(bytes(result))
        )

    def query_extensions(self) -> Iterator[int]:
        """Answer an `SSH_AGENTC_EXTENSION` request.

        Yields:
            The bytes payload of the response, without the protocol
            framing.  The payload is yielded byte by byte, as an
            iterable of 8-bit integers.

        """
        yield _types.SSH_AGENT.EXTENSION_RESPONSE.value
        yield from ssh_agent.SSHAgentClient.string(b"query")
        extension_answers = [
            b"query",
            b"list-extended@putty.projects.tartarus.org",
        ]
        for a in extension_answers:
            yield from ssh_agent.SSHAgentClient.string(a)

    def request_identities(
        self, *, list_extended: bool = False
    ) -> Iterator[int]:
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
            yield _types.SSH_AGENT.SUCCESS.value
        else:
            yield _types.SSH_AGENT.IDENTITIES_ANSWER.value
        signature_classes = [
            tests.data.SSHTestKeyDeterministicSignatureClass.SPEC,
        ]
        if (
            "list-extended@putty.projects.tartarus.org"
            in self.enabled_extensions
        ):
            signature_classes.append(
                tests.data.SSHTestKeyDeterministicSignatureClass.RFC_6979
            )
        keys = [
            v
            for v in tests.data.ALL_KEYS.values()
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

    def sign(self) -> bytes:
        """Answer an `SSH_AGENTC_SIGN_REQUEST` request.

        Returns:
            The bytes payload of the response, without the protocol
            framing.

        """
        try_rfc6979 = (
            "list-extended@putty.projects.tartarus.org"
            in self.enabled_extensions
        )
        spec = tests.data.SSHTestKeyDeterministicSignatureClass.SPEC
        rfc6979 = tests.data.SSHTestKeyDeterministicSignatureClass.RFC_6979
        key_blob, rest = ssh_agent.SSHAgentClient.unstring_prefix(
            self.receive_from_client[self.HEADER_SIZE + self.CODE_SIZE :]
        )
        sign_data, rest = ssh_agent.SSHAgentClient.unstring_prefix(rest)
        if len(rest) != 4:
            raise ValueError(self._INVALID_REQUEST)
        flags = int.from_bytes(rest, "big")
        if flags:
            raise ValueError(self._UNSUPPORTED_REQUEST)
        if sign_data != vault.Vault.UUID:
            raise ValueError(self._UNSUPPORTED_REQUEST)
        for key in tests.data.ALL_KEYS.values():
            if key.public_key_data == key_blob:
                if spec in key.expected_signatures:
                    return int.to_bytes(
                        _types.SSH_AGENT.SIGN_RESPONSE.value, 1, "big"
                    ) + ssh_agent.SSHAgentClient.string(
                        key.expected_signatures[spec].signature
                    )
                if try_rfc6979 and rfc6979 in key.expected_signatures:
                    return int.to_bytes(
                        _types.SSH_AGENT.SIGN_RESPONSE.value, 1, "big"
                    ) + ssh_agent.SSHAgentClient.string(
                        key.expected_signatures[rfc6979].signature
                    )
                raise ValueError(self._UNSUPPORTED_REQUEST)
        raise ValueError(self._UNSUPPORTED_REQUEST)


# Standard variant
# ----------------


@socketprovider.SocketProvider.register("stub_with_address")
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
    "stub_with_address_and_deterministic_dsa"
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
