# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for `derivepassphrase.ssh_agent`: basic tests."""

from __future__ import annotations

import base64
import collections
import contextlib
import ctypes
import importlib.metadata
import io
import re
import socket
import sys
import types
from typing import TYPE_CHECKING, NamedTuple

import click
import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import TypeAlias

from derivepassphrase import _types, ssh_agent, vault
from derivepassphrase._internals import cli_helpers
from derivepassphrase.ssh_agent import socketprovider
from tests import data, machinery
from tests.data import callables
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from typing_extensions import Any, Literal, Self

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup


class Parametrize(types.SimpleNamespace):
    BAD_ENTRY_POINTS = pytest.mark.parametrize(
        "additional_entry_points",
        [
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=data.faulty_entry_callable.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: faulty_entry_callable",
                    ),
                ],
                id="not-callable",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=data.faulty_entry_name_exists.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: faulty_entry_name_exists",
                    ),
                ],
                id="name-already-exists",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=data.faulty_entry_alias_exists.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: faulty_entry_alias_exists",
                    ),
                ],
                id="alias-already-exists",
            ),
        ],
    )
    GOOD_ENTRY_POINTS = pytest.mark.parametrize(
        "additional_entry_points",
        [
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=data.ssh_auth_sock_on_posix_entry.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: ssh_auth_sock_on_posix_entry",
                    ),
                    importlib.metadata.EntryPoint(
                        name=data.ssh_auth_sock_on_windows_entry.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: ssh_auth_sock_on_windows_entry",
                    ),
                ],
                id="existing-entries",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=callables.provider_entry1.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data.callables: provider_entry1",
                    ),
                    importlib.metadata.EntryPoint(
                        name=callables.provider_entry2.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data.callables: provider_entry2",
                    ),
                ],
                id="new-entries",
            ),
        ],
    )
    EXISTING_REGISTRY_ENTRIES = pytest.mark.parametrize(
        "existing",
        [
            _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX,
            _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_WINDOWS,
        ],
        ids=str,
    )
    SSH_STRING_EXCEPTIONS = pytest.mark.parametrize(
        ["input", "exc_type", "exc_pattern"],
        [
            pytest.param(
                "some string", TypeError, "invalid payload type", id="str"
            ),
        ],
    )
    UINT32_EXCEPTIONS = pytest.mark.parametrize(
        ["input", "exc_type", "exc_pattern"],
        [
            pytest.param(
                10000000000000000,
                OverflowError,
                "int too big to convert",
                id="10000000000000000",
            ),
            pytest.param(
                -1,
                OverflowError,
                "can't convert negative int to unsigned",
                id="-1",
            ),
        ],
    )
    SSH_UNSTRING_EXCEPTIONS = pytest.mark.parametrize(
        ["input", "exc_type", "exc_pattern", "has_trailer", "parts"],
        [
            pytest.param(
                b"ssh",
                ValueError,
                "malformed SSH byte string",
                False,
                None,
                id="unencoded",
            ),
            pytest.param(
                b"\x00\x00\x00\x08ssh-rsa",
                ValueError,
                "malformed SSH byte string",
                False,
                None,
                id="truncated",
            ),
            pytest.param(
                b"\x00\x00\x00\x04XXX trailing text",
                ValueError,
                "malformed SSH byte string",
                True,
                (b"XXX ", b"trailing text"),
                id="trailing-data",
            ),
        ],
    )
    SSH_STRING_INPUT = pytest.mark.parametrize(
        ["input", "expected"],
        [
            pytest.param(
                b"ssh-rsa",
                b"\x00\x00\x00\x07ssh-rsa",
                id="ssh-rsa",
            ),
            pytest.param(
                b"ssh-ed25519",
                b"\x00\x00\x00\x0bssh-ed25519",
                id="ssh-ed25519",
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(b"ssh-ed25519"),
                b"\x00\x00\x00\x0f\x00\x00\x00\x0bssh-ed25519",
                id="string(ssh-ed25519)",
            ),
        ],
    )
    SSH_UNSTRING_INPUT = pytest.mark.parametrize(
        ["input", "expected"],
        [
            pytest.param(
                b"\x00\x00\x00\x07ssh-rsa",
                b"ssh-rsa",
                id="ssh-rsa",
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(b"ssh-ed25519"),
                b"ssh-ed25519",
                id="ssh-ed25519",
            ),
        ],
    )
    UINT32_INPUT = pytest.mark.parametrize(
        ["input", "expected"],
        [
            pytest.param(16777216, b"\x01\x00\x00\x00", id="16777216"),
        ],
    )
    IO_OPERATIONS_ON_HANDLES = pytest.mark.parametrize(
        "io_operation",
        [
            lambda handle: handle.recv(1),
            lambda handle: handle.sendall(b"Hello, world!"),
        ],
        ids=["recv", "sendall"],
    )
    SIGN_ERROR_RESPONSES = pytest.mark.parametrize(
        [
            "key",
            "check",
            "response_code",
            "response",
            "exc_type",
            "exc_pattern",
        ],
        [
            pytest.param(
                b"invalid-key",
                True,
                _types.SSH_AGENT.FAILURE,
                b"",
                KeyError,
                "target SSH key not loaded into agent",
                id="key-not-loaded",
            ),
            pytest.param(
                data.SUPPORTED_KEYS["ed25519"].public_key_data,
                True,
                _types.SSH_AGENT.FAILURE,
                b"",
                ssh_agent.SSHAgentFailedError,
                "failed to complete the request",
                id="failed-to-complete",
            ),
        ],
    )
    SSH_KEY_SELECTION = pytest.mark.parametrize(
        ["key", "single"],
        [
            (value.public_key_data, False)
            for value in data.SUPPORTED_KEYS.values()
        ]
        + [(callables.list_keys_singleton()[0].key, True)],
        ids=[*data.SUPPORTED_KEYS.keys(), "singleton"],
    )
    SH_EXPORT_LINES = pytest.mark.parametrize(
        ["line", "env_name", "value"],
        [
            pytest.param(
                "SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK;",
                "SSH_AUTH_SOCK",
                "/tmp/pageant.user/pageant.27170",
                id="value-export-semicolon-pageant",
            ),
            pytest.param(
                "SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270; export SSH_AUTH_SOCK;",
                "SSH_AUTH_SOCK",
                "/tmp/ssh-3CSTC1W5M22A/agent.27270",
                id="value-export-semicolon-openssh",
            ),
            pytest.param(
                "SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK",
                "SSH_AUTH_SOCK",
                "/tmp/pageant.user/pageant.27170",
                id="value-export-pageant",
            ),
            pytest.param(
                "export SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270;",
                "SSH_AUTH_SOCK",
                "/tmp/ssh-3CSTC1W5M22A/agent.27270",
                id="export-value-semicolon-openssh",
            ),
            pytest.param(
                "export SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170",
                "SSH_AUTH_SOCK",
                "/tmp/pageant.user/pageant.27170",
                id="export-value-pageant",
            ),
            pytest.param(
                "SSH_AGENT_PID=27170; export SSH_AGENT_PID;",
                "SSH_AGENT_PID",
                "27170",
                id="pid-export-semicolon",
            ),
            pytest.param(
                "SSH_AGENT_PID=27170; export SSH_AGENT_PID",
                "SSH_AGENT_PID",
                "27170",
                id="pid-export",
            ),
            pytest.param(
                "export SSH_AGENT_PID=27170;",
                "SSH_AGENT_PID",
                "27170",
                id="export-pid-semicolon",
            ),
            pytest.param(
                "export SSH_AGENT_PID=27170",
                "SSH_AGENT_PID",
                "27170",
                id="export-pid",
            ),
            pytest.param(
                "export VARIABLE=value; export OTHER_VARIABLE=other_value;",
                "VARIABLE",
                None,
                id="export-too-much",
            ),
            pytest.param(
                "VARIABLE=value",
                "VARIABLE",
                None,
                id="no-export",
            ),
        ],
    )
    PUBLIC_KEY_DATA = pytest.mark.parametrize(
        "public_key_struct",
        list(data.SUPPORTED_KEYS.values()),
        ids=list(data.SUPPORTED_KEYS.keys()),
    )
    REQUEST_ERROR_RESPONSES = pytest.mark.parametrize(
        ["request_code", "response_code", "exc_type", "exc_pattern"],
        [
            pytest.param(
                _types.SSH_AGENTC.REQUEST_IDENTITIES,
                _types.SSH_AGENT.SUCCESS,
                ssh_agent.SSHAgentFailedError,
                re.escape(
                    "[Code {:d}]".format(  # noqa: UP032
                        int(_types.SSH_AGENT.IDENTITIES_ANSWER)
                    )
                ),
                id="REQUEST_IDENTITIES-expect-SUCCESS",
            ),
        ],
    )
    TRUNCATED_AGENT_RESPONSES = pytest.mark.parametrize(
        "response",
        [
            b"\x00\x00",
            b"\x00\x00\x00\x1f some bytes missing",
        ],
        ids=["in-header", "in-body"],
    )
    LIST_KEYS_ERROR_RESPONSES = pytest.mark.parametrize(
        ["response_code", "response", "exc_type", "exc_pattern"],
        [
            pytest.param(
                _types.SSH_AGENT.FAILURE,
                b"",
                ssh_agent.SSHAgentFailedError,
                "failed to complete the request",
                id="failed-to-complete",
            ),
            pytest.param(
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b"\x00\x00\x00\x01",
                EOFError,
                "truncated response",
                id="truncated-response",
            ),
            pytest.param(
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b"\x00\x00\x00\x00abc",
                ssh_agent.TrailingDataError,
                "Overlong response",
                id="overlong-response",
            ),
        ],
    )
    QUERY_EXTENSIONS_MALFORMED_RESPONSES = pytest.mark.parametrize(
        "response_data",
        [
            pytest.param(b"\xde\xad\xbe\xef", id="truncated"),
            pytest.param(
                b"\x00\x00\x00\x0fwrong extension", id="wrong-extension"
            ),
            pytest.param(
                b"\x00\x00\x00\x05query\xde\xad\xbe\xef", id="with-trailer"
            ),
            pytest.param(
                b"\x00\x00\x00\x05query\x00\x00\x00\x04ext1\x00\x00",
                id="with-extra-fields",
            ),
        ],
    )
    ALL_SSH_TEST_KEYS = pytest.mark.parametrize(
        ["ssh_test_key_type", "ssh_test_key"],
        list(data.ALL_KEYS.items()),
        ids=data.ALL_KEYS.keys(),
    )
    RESOLVE_CHAINS = pytest.mark.parametrize(
        ["terminal", "chain"],
        [
            pytest.param("callable", ["a"], id="callable-1"),
            pytest.param("callable", ["a", "b", "c", "d"], id="callable-4"),
            pytest.param("alias", ["e"], id="alias-1"),
            pytest.param("alias", ["e", "f", "g", "h", "i"], id="alias-5"),
            pytest.param("unimplemented", ["j"], id="unimplemented-1"),
            pytest.param("unimplemented", ["j", "k"], id="unimplemented-2"),
        ],
    )


class Strategies:
    """Common hypothesis data generation strategies."""

    @staticmethod
    def select_invalid_pipe_names(candidate: str) -> bool:
        """Select candidate strings that are invalid named pipe names."""
        candidate = candidate.lower().replace("/", "\\")
        return not candidate.startswith(socketprovider.PIPE_PREFIX)

    @classmethod
    def bad_named_pipe_names(cls) -> strategies.SearchStrategy[str]:
        r"""Generate invalid names for Windows named pipes.

        Invalid named pipe names do not lie below the `\\.\pipe\` path.
        They also may or may not contain characters that are invalid
        in paths on The Annoying OS.

        """
        # This is an environment string on The Annoying OS, so it must
        # at least be a non-empty C string, i.e., without embedded NULs.
        return strategies.text(
            alphabet=strategies.characters(min_codepoint=1), min_size=1
        ).filter(cls.select_invalid_pipe_names)


class TestStaticFunctionality:
    """Test the static functionality of the `ssh_agent` module."""

    @staticmethod
    def as_ssh_string(bytestring: bytes) -> bytes:
        """Return an encoded SSH string from a bytestring.

        This is a helper function for hypothesis data generation.

        """
        return int.to_bytes(len(bytestring), 4, "big") + bytestring

    @staticmethod
    def canonicalize1(data: bytes) -> bytes:
        """Return an encoded SSH string from a bytestring.

        This is a helper function for hypothesis testing.

        References:

          * [David R. MacIver: Another invariant to test for
            encoders][DECODE_ENCODE]

        [DECODE_ENCODE]: https://hypothesis.works/articles/canonical-serialization/

        """
        return ssh_agent.SSHAgentClient.string(
            ssh_agent.SSHAgentClient.unstring(data)
        )

    @staticmethod
    def canonicalize2(data: bytes) -> bytes:
        """Return an encoded SSH string from a bytestring.

        This is a helper function for hypothesis testing.

        References:

          * [David R. MacIver: Another invariant to test for
            encoders][DECODE_ENCODE]

        [DECODE_ENCODE]: https://hypothesis.works/articles/canonical-serialization/

        """
        unstringed, trailer = ssh_agent.SSHAgentClient.unstring_prefix(data)
        assert not trailer
        return ssh_agent.SSHAgentClient.string(unstringed)


class TestShellExportScriptParsing:
    """Test the shell export script parsing utility function."""

    @Parametrize.SH_EXPORT_LINES
    def test_sh_export_line_parsing(
        self, line: str, env_name: str, value: str | None
    ) -> None:
        """[`tests.data.callables.parse_sh_export_line`][] works."""
        if value is not None:
            assert (
                callables.parse_sh_export_line(line, env_name=env_name)
                == value
            )
        else:
            with pytest.raises(ValueError, match="Cannot parse sh line:"):
                callables.parse_sh_export_line(line, env_name=env_name)


class TestSSHProtocolDatatypes(TestStaticFunctionality):
    """Tests for the utility functions for the SSH protocol datatypes."""

    @Parametrize.UINT32_INPUT
    def test_uint32(self, input: int, expected: bytes | bytearray) -> None:
        """`uint32` encoding works."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert uint32(input) == expected

    @hypothesis.given(strategies.integers(min_value=0, max_value=0xFFFFFFFF))
    @hypothesis.example(0xDEADBEEF).via("manual, pre-hypothesis example")
    def test_uint32_from_number(self, num: int) -> None:
        """`uint32` encoding works, starting from numbers."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert int.from_bytes(uint32(num), "big", signed=False) == num

    @hypothesis.given(strategies.binary(min_size=4, max_size=4))
    @hypothesis.example(b"\xde\xad\xbe\xef").via(
        "manual, pre-hypothesis example"
    )
    def test_uint32_from_bytestring(self, bytestring: bytes) -> None:
        """`uint32` encoding works, starting from length four byte strings."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert (
            uint32(int.from_bytes(bytestring, "big", signed=False))
            == bytestring
        )

    @Parametrize.SSH_STRING_INPUT
    def test_string(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        """SSH string encoding works."""
        string = ssh_agent.SSHAgentClient.string
        assert bytes(string(input)) == expected

    @hypothesis.given(strategies.binary(max_size=0x0001FFFF))
    @hypothesis.example(b"DEADBEEF" * 10000).via(
        "manual, pre-hypothesis example with highest order bit set"
    )
    def test_string_from_bytestring(self, bytestring: bytes) -> None:
        """SSH string encoding works, starting from a byte string."""
        res = ssh_agent.SSHAgentClient.string(bytestring)
        assert res.startswith((b"\x00\x00", b"\x00\x01"))
        assert int.from_bytes(res[:4], "big", signed=False) == len(bytestring)
        assert res[4:] == bytestring

    @Parametrize.SSH_UNSTRING_INPUT
    def test_unstring(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        """SSH string decoding works."""
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        assert bytes(unstring(input)) == expected
        assert tuple(bytes(x) for x in unstring_prefix(input)) == (
            expected,
            b"",
        )

    @hypothesis.given(strategies.binary(max_size=0x00FFFFFF))
    @hypothesis.example(b"\x00\x00\x00\x07ssh-rsa").via(
        "manual, pre-hypothesis example to attempt to detect double-decoding"
    )
    @hypothesis.example(b"\x00\x00\x00\x01").via(
        "detect no-op encoding via ill-formed SSH string"
    )
    def test_unstring_of_string_of_data(self, bytestring: bytes) -> None:
        """SSH string decoding of encoded SSH strings works.

        References:

          * [David R. MacIver: The Encode/Decode invariant][ENCODE_DECODE]

        [ENCODE_DECODE]: https://hypothesis.works/articles/encode-decode-invariant/

        """
        string = ssh_agent.SSHAgentClient.string
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        encoded = string(bytestring)
        assert unstring(encoded) == bytestring
        assert unstring_prefix(encoded) == (bytestring, b"")
        trailing_data = b"  trailing data"
        encoded2 = string(bytestring) + trailing_data
        assert unstring_prefix(encoded2) == (bytestring, trailing_data)

    @hypothesis.given(
        strategies.binary(max_size=0x00FFFFFF).map(
            # Scoping issues, and the fact that staticmethod objects
            # (before class finalization) are not callable, necessitate
            # wrapping this staticmethod call in a lambda.
            lambda x: TestStaticFunctionality.as_ssh_string(x)  # noqa: PLW0108
        ),
    )
    def test_string_of_unstring_of_data(self, encoded: bytes) -> None:
        """SSH string decoding of encoded SSH strings works.

        References:

          * [David R. MacIver: Another invariant to test for
            encoders][DECODE_ENCODE]

        [DECODE_ENCODE]: https://hypothesis.works/articles/canonical-serialization/

        """
        canonical_functions = [self.canonicalize1, self.canonicalize2]
        for canon1 in canonical_functions:
            for canon2 in canonical_functions:
                assert canon1(encoded) == canon2(encoded)
                assert canon1(canon2(encoded)) == canon1(encoded)

    @Parametrize.UINT32_EXCEPTIONS
    def test_uint32_exceptions(
        self, input: int, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """`uint32` encoding fails for out-of-bound values."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        with pytest.raises(exc_type, match=exc_pattern):
            uint32(input)

    @Parametrize.SSH_STRING_EXCEPTIONS
    def test_string_exceptions(
        self, input: Any, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """SSH string encoding fails for non-strings."""
        string = ssh_agent.SSHAgentClient.string
        with pytest.raises(exc_type, match=exc_pattern):
            string(input)

    @Parametrize.SSH_UNSTRING_EXCEPTIONS
    def test_unstring_exceptions(
        self,
        input: bytes | bytearray,
        exc_type: type[Exception],
        exc_pattern: str,
        has_trailer: bool,
        parts: tuple[bytes | bytearray, bytes | bytearray] | None,
    ) -> None:
        """SSH string decoding fails for invalid values."""
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        with pytest.raises(exc_type, match=exc_pattern):
            unstring(input)
        if has_trailer:
            assert tuple(bytes(x) for x in unstring_prefix(input)) == parts
        else:
            with pytest.raises(exc_type, match=exc_pattern):
                unstring_prefix(input)


class TestSSHAgentSocketProviderRegistry:
    """Tests for the SSH agent socket provider registry."""

    def test_resolve(
        self,
    ) -> None:
        """Resolving entries in the socket provider registry works."""
        registry = socketprovider.SocketProvider.registry
        resolve = socketprovider.SocketProvider.resolve
        lookup = socketprovider.SocketProvider.lookup
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setitem(registry, "stub_agent", None)
            assert callable(lookup("native"))
            assert callable(resolve("native"))
            assert lookup("stub_agent") is None
            with pytest.raises(NotImplementedError):
                resolve("stub_agent")

    @Parametrize.RESOLVE_CHAINS
    def test_resolve_chains(
        self,
        terminal: Literal["unimplemented", "alias", "callable"],
        chain: list[str],
    ) -> None:
        """Resolving a chain of providers works."""
        registry = socketprovider.SocketProvider.registry
        resolve = socketprovider.SocketProvider.resolve
        lookup = socketprovider.SocketProvider.lookup
        try:
            implementation = resolve("native")
        except NotImplementedError:  # pragma: no cover
            pytest.fail("Native SSH agent socket provider is unavailable?!")
        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        target = (
            None
            if terminal == "unimplemented"
            else "native"
            if terminal == "alias"
            else implementation
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            for link in chain:
                monkeypatch.setitem(registry, link, target)
                target = link
            for link in chain:
                assert lookup(link) == (
                    implementation if terminal != "unimplemented" else None
                )
                if terminal == "unimplemented":
                    with pytest.raises(NotImplementedError):
                        resolve(link)
                else:
                    assert resolve(link) == implementation

    @hypothesis.given(
        terminal=strategies.sampled_from([
            "unimplemented",
            "alias",
            "callable",
        ]),
        chain=strategies.lists(
            strategies.sampled_from([
                "c1",
                "c2",
                "c3",
                "c4",
                "c5",
                "c6",
                "c7",
                "c8",
                "c9",
                "c10",
            ]),
            min_size=1,
            unique=True,
        ),
    )
    def test_resolve_chains2(
        self,
        terminal: Literal["unimplemented", "alias", "callable"],
        chain: list[str],
    ) -> None:
        """Resolving a chain of providers works."""
        registry = socketprovider.SocketProvider.registry
        resolve = socketprovider.SocketProvider.resolve
        lookup = socketprovider.SocketProvider.lookup
        try:
            implementation = resolve("native")
        except NotImplementedError:  # pragma: no cover
            hypothesis.note(f"{registry = }")
            pytest.fail("Native SSH agent socket provider is unavailable?!")
        # TODO(the-13th-letter): Rewrite using structural pattern matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        target = (
            None
            if terminal == "unimplemented"
            else "native"
            if terminal == "alias"
            else implementation
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            for link in chain:
                monkeypatch.setitem(registry, link, target)
                target = link
            for link in chain:
                assert lookup(link) == (
                    implementation if terminal != "unimplemented" else None
                )
                if terminal == "unimplemented":
                    with pytest.raises(NotImplementedError):
                        resolve(link)
                else:
                    assert resolve(link) == implementation

    @Parametrize.GOOD_ENTRY_POINTS
    def test_find_all_socket_providers(
        self,
        additional_entry_points: list[importlib.metadata.EntryPoint],
    ) -> None:
        """Finding all SSH agent socket providers works."""
        resolve = socketprovider.SocketProvider.resolve
        old_registry = socketprovider.SocketProvider.registry
        with pytest_machinery.faked_entry_point_list(
            additional_entry_points, remove_conflicting_entries=False
        ) as names:
            socketprovider.SocketProvider._find_all_ssh_agent_socket_providers()
            for name in names:
                assert name in socketprovider.SocketProvider.registry
                assert resolve(name) in {
                    callables.provider_entry_provider,
                    *old_registry.values(),
                }

    @Parametrize.BAD_ENTRY_POINTS
    def test_find_all_socket_providers_errors(
        self,
        additional_entry_points: list[importlib.metadata.EntryPoint],
    ) -> None:
        """Finding faulty SSH agent socket providers raises errors."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                pytest_machinery.faked_entry_point_list(
                    additional_entry_points, remove_conflicting_entries=False
                )
            )
            stack.enter_context(pytest.raises(AssertionError))
            socketprovider.SocketProvider._find_all_ssh_agent_socket_providers()

    def test_overwriting_existing_entries(
        self,
    ) -> None:
        """The registry forbids incompatibly overwriting entries."""
        registry = socketprovider.SocketProvider.registry.copy()
        resolve = socketprovider.SocketProvider.resolve
        register = socketprovider.SocketProvider.register

        def ancestry_chain(name: str) -> Iterator[str]:
            current: _types.SSHAgentSocketProvider | str | None = name
            seen: set[_types.SSHAgentSocketProvider | str | None] = set()
            while isinstance(current, str) and current not in seen:
                yield current
                seen.add(current)
                current = registry[current]

        # Entries with at least one level of alias resolving, and where each
        # entry ultimately resolves to a different provider.  They needn't
        # technically be leaves of the socket provider forest, but "leaves"
        # emphasizes the quality we are looking for.
        leaves = [
            _types.BuiltinSSHAgentSocketProvider.POSIX,
            _types.BuiltinSSHAgentSocketProvider.WINDOWS,
        ]
        assert all([isinstance(registry.get(leaf), str) for leaf in leaves]), (
            "Registry is shaped incompatibly; cannot determine base entries"
        )
        bases = [resolve(leaf) for leaf in leaves]
        names = [list(ancestry_chain(leaf)) for leaf in leaves]

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", registry
            )
            # Registering names with different values is forbidden...
            with pytest.raises(ValueError, match="already registered"):
                register(names[0][0])(bases[1])
            with pytest.raises(ValueError, match="already registered"):
                register(names[1][0])(bases[0])
            # ...even if other names of the same registration are valid.
            with pytest.raises(ValueError, match="already registered"):
                register(names[0][0], names[1][1])(bases[0])
            with pytest.raises(ValueError, match="already registered"):
                register(names[1][0], names[0][1])(bases[1])

    def test_resolve_non_existant_entries(
        self,
    ) -> None:
        """Resolving a non-existant entry fails."""
        new_registry = {
            "posix": socketprovider.SocketProvider.resolve("posix"),
            "windows": socketprovider.SocketProvider.resolve("windows"),
        }
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", new_registry
            )
            with pytest.raises(socketprovider.NoSuchProviderError):
                socketprovider.SocketProvider.resolve("native")

    def test_register_new_entry(
        self,
    ) -> None:
        """Registering new entries works."""

        def socket_provider() -> _types.SSHAgentSocket:
            raise AssertionError

        names = ["spam", "ham", "eggs", "parrot"]
        new_registry = {
            "posix": socketprovider.SocketProvider.resolve("posix"),
            "windows": socketprovider.SocketProvider.resolve("windows"),
        }
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", new_registry
            )
            assert not any(
                map(socketprovider.SocketProvider.registry.__contains__, names)
            )
            assert (
                socketprovider.SocketProvider.register(*names)(socket_provider)
                is socket_provider
            )
            assert all(
                map(socketprovider.SocketProvider.registry.__contains__, names)
            )
            assert all([
                socketprovider.SocketProvider.resolve(n) is socket_provider
                for n in names
            ])

    @Parametrize.EXISTING_REGISTRY_ENTRIES
    def test_register_old_entry(
        self,
        existing: str,
    ) -> None:
        """Registering old entries works."""

        provider = socketprovider.SocketProvider.resolve(existing)
        new_registry = {
            _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX: socketprovider.SocketProvider.resolve(
                _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX
            ),
            _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_WINDOWS: socketprovider.SocketProvider.resolve(
                _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_WINDOWS
            ),
            _types.BuiltinSSHAgentSocketProvider.UNIX_DOMAIN: _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_POSIX,
            _types.BuiltinSSHAgentSocketProvider.WINDOWS_NAMED_PIPE: _types.BuiltinSSHAgentSocketProvider.SSH_AUTH_SOCK_ON_WINDOWS,
        }
        names = [
            k
            for k, v in socketprovider.SocketProvider.registry.items()
            if v == existing
        ]
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", new_registry
            )
            assert names, (
                f"Existing SSH agent socket provider entry "
                f"{existing!r} is not existing?!"
            )
            # TODO(the-13th-letter): Do we require, forbid, or not care
            # if `names` discovers aliases not present in the mocked
            # registry?  Currently, the "ssh_auth_sock" alias for
            # "ssh_auth_sock_on_posix" would be discovered, but
            # "ssh_auth_sock_on_windows" has no undiscovered aliases.
            #
            # assert not
            # all(map(socketprovider.SocketProvider.registry.__contains__,
            # names))
            assert (
                socketprovider.SocketProvider.register(existing, *names)(
                    provider
                )
                is provider
            )
            assert all(
                map(socketprovider.SocketProvider.registry.__contains__, names)
            )
            assert all([
                socketprovider.SocketProvider.resolve(n) is provider
                for n in [existing, *names]
            ])


class TestAgentSigning:
    """Test actually talking to the SSH agent: signing data."""

    @Parametrize.ALL_SSH_TEST_KEYS
    def test_sign_data_via_agent(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        ssh_test_key_type: str,
        ssh_test_key: data.SSHTestKey,
    ) -> None:
        """Signing data with specific SSH keys works iff the key is suitable.

        Single tests may abort early (skip) if the indicated key is not
        loaded in the agent.  Presumably this means the key type is
        unsupported.

        """
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = ssh_test_key.public_key_data
        if public_key_data not in key_comment_pairs:  # pragma: no cover
            pytest.skip(f"prerequisite {ssh_test_key_type} SSH key not loaded")
        if ssh_test_key.is_suitable():
            assert (
                data.SSHTestKeyDeterministicSignatureClass.SPEC
                in ssh_test_key.expected_signatures
            )
            sig = ssh_test_key.expected_signatures[
                data.SSHTestKeyDeterministicSignatureClass.SPEC
            ]
            expected_signature = sig.signature
            derived_passphrase = sig.derived_passphrase
            signature = bytes(
                client.sign(payload=vault.Vault.UUID, key=public_key_data)
            )
            assert signature == expected_signature, (
                f"SSH signature mismatch ({ssh_test_key_type})"
            )
            signature2 = bytes(
                client.sign(payload=vault.Vault.UUID, key=public_key_data)
            )
            assert signature2 == expected_signature, (
                f"SSH signature mismatch ({ssh_test_key_type})"
            )
            assert (
                vault.Vault.phrase_from_key(public_key_data, conn=client)
                == derived_passphrase
            ), f"SSH signature mismatch ({ssh_test_key_type})"
        else:
            assert (
                data.SSHTestKeyDeterministicSignatureClass.SPEC
                not in ssh_test_key.expected_signatures
            )
            assert not vault.Vault.is_suitable_ssh_key(
                public_key_data, client=None
            ), f"Expected {ssh_test_key_type} key to be unsuitable in general"
            if vault.Vault.is_suitable_ssh_key(
                public_key_data, client=client
            ):  # pragma: no cover [external]
                potential_signatures = {
                    sig_class: sig.signature
                    for sig_class, sig in ssh_test_key.expected_signatures.items()
                    if sig_class
                    != data.SSHTestKeyDeterministicSignatureClass.SPEC
                }
                signature = bytes(
                    client.sign(payload=vault.Vault.UUID, key=public_key_data)
                )
                assert signature in potential_signatures.values()
            else:  # pragma: no cover [external]
                with pytest.raises(ValueError, match="unsuitable SSH key"):
                    vault.Vault.phrase_from_key(public_key_data, conn=client)


class TestSuitableKeys:
    """Test actually talking to the SSH agent: determining suitable keys."""

    @Parametrize.SSH_KEY_SELECTION
    def test_ssh_key_selector(
        self,
        monkeypatch: pytest.MonkeyPatch,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        key: bytes,
        single: bool,
    ) -> None:
        """The key selector presents exactly the suitable keys.

        "Suitable" here means suitability for this SSH agent
        specifically.

        """
        client = ssh_agent_client_with_test_keys_loaded

        monkeypatch.setattr(
            ssh_agent.SSHAgentClient,
            "list_keys",
            callables.list_keys_singleton if single else callables.list_keys,
        )
        raw_keys_list = (
            callables.list_keys_singleton()
            if single
            else callables.list_keys()
        )
        keys = [
            pair.key
            for pair in raw_keys_list
            if vault.Vault.is_suitable_ssh_key(pair.key, client=client)
        ]
        n = len(keys)
        if single or n == 1:
            input_text = "yes\n"
            text = "Use this key? yes\n"
        else:
            input_text = f"{1 + keys.index(key)}\n"
            text = (
                f"Your selection? (1-{n}, leave empty to abort): {input_text}"
            )
        b64_key = base64.standard_b64encode(key).decode("ASCII")

        @click.command()
        def driver() -> None:
            """Call [`cli_helpers.select_ssh_key`][] directly, as a command."""
            key = cli_helpers.select_ssh_key(
                client,
                error_callback=lambda s, *_args: pytest.fail(str(s)),
                warning_callback=lambda s, *_args: pytest.fail(str(s)),
            )
            click.echo(base64.standard_b64encode(key).decode("ASCII"))

        runner = machinery.CliRunner(mix_stderr=True)
        result = runner.invoke(
            driver, [], input=input_text, catch_exceptions=True
        )
        for snippet in ("Suitable SSH keys:\n", text, f"\n{b64_key}\n"):
            assert result.clean_exit(output=snippet), "expected clean exit"


class TestConstructorFailures:
    """Test actually talking to the SSH agent: constructor failures."""

    def test_constructor_bad_running_agent(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
    ) -> None:
        """Fail if the agent address is invalid."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            new_socket_name = (
                running_ssh_agent.socket + "~"
                if isinstance(running_ssh_agent.socket, str)
                else "<invalid//address>"
            )
            monkeypatch.setenv("SSH_AUTH_SOCK", new_socket_name)
            with pytest.raises(OSError):  # noqa: PT011
                ssh_agent.SSHAgentClient()

    def test_constructor_no_af_unix_support(self) -> None:
        """Fail without [`socket.AF_UNIX`][] support."""
        assert "posix" in socketprovider.SocketProvider.registry
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("SSH_AUTH_SOCK", "the value doesn't matter")
            monkeypatch.delattr(socket, "AF_UNIX", raising=False)
            with pytest.raises(
                NotImplementedError,
                match="UNIX domain sockets",
            ):
                ssh_agent.SSHAgentClient(socket="posix")

    def test_no_ssh_agent_socket_provider_available(
        self,
    ) -> None:
        """Fail if no SSH agent socket provider is available."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setitem(
                socketprovider.SocketProvider.registry, "stub_agent", None
            )
            with pytest.raises(ExceptionGroup) as excinfo:
                ssh_agent.SSHAgentClient(
                    socket=["stub_agent", "stub_agent", "stub_agent"]
                )
            assert all([
                isinstance(e, NotImplementedError)
                for e in excinfo.value.exceptions
            ])


class TestOtherConstructorFeatures:
    """Test actually talking to the SSH agent: other constructor features."""

    def test_explicit_socket(
        self,
        spawn_ssh_agent: data.SpawnedSSHAgentInfo,
    ) -> None:
        conn = spawn_ssh_agent.client._connection
        ssh_agent.SSHAgentClient(socket=conn)


class TestAgentErrorResponses:
    """Test actually talking to the SSH agent: errors from the SSH agent."""

    class Request(NamedTuple):
        """A request for the SSH agent protocol.

        Attributes:
            code:
                The expected request code.
            payload:
                The expected payload.  Optional.

        """

        code: _types.SSH_AGENTC | int
        """"""
        payload: bytes
        """"""

    class Response(NamedTuple):
        """A response for the SSH agent protocol.

        Attributes:
            code:
                The desired response code.
            payload:
                The desired response payload.

        """

        code: _types.SSH_AGENT | int
        """"""
        payload: bytes
        """"""

    class _RequestResponseIOQueue:
        """A response queue for the SSH agent protocol.

        This queue wraps a map of request messages
        ([`Request`][TestAgentErrorResponses.Request]) to multiple
        response messages
        ([`Response`][TestAgentErrorResponses.Response]).  Whenever
        [`_request_message`][] is called with a payload that matches
        a [`Request`][TestAgentErrorResponses.Response] from the map,
        the corresponding [`Response`][TestAgentErrorResponses.Response]
        objects are added to the queue, to be read by subsequent
        [`_response_pair`][] calls.

        Use this agent stub implementation if you are modelling
        well-formed requests and responses, without network errors or
        protocol framing errors.  If the latter are needed, a custom SSH
        agent implementation may be necessary.

        The queue is a context manager.  When entered or exited, it
        verifies that the queue is empty.

        """

        def __init__(
            self,
            request_responses_mapping: Mapping[
                TestAgentErrorResponses.Request,
                Sequence[TestAgentErrorResponses.Response],
            ],
        ) -> None:
            self.responses_map = request_responses_mapping
            self.queue: collections.deque[TestAgentErrorResponses.Response] = (
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
            if (exc_type, exc_value, exc_tb) != (None, None, None):
                return False
            assert not self, (
                f"Agent I/O queue still has contents: {self.queue!r}"
            )
            return False

        def _send_request_message(
            self,
            request_code: int | _types.SSH_AGENTC,
            payload: bytes | bytearray,
        ) -> None:
            req = TestAgentErrorResponses.Request(request_code, bytes(payload))
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

    @contextlib.contextmanager
    def _setup_agent_and_request_handler(
        self, request_responses_map: Mapping[Request, Sequence[Response]], /
    ) -> Iterator[tuple[pytest.MonkeyPatch, ssh_agent.SSHAgentClient]]:
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            client = stack.enter_context(
                ssh_agent.SSHAgentClient.ensure_agent_subcontext()
            )
            agent_io_queue = self._RequestResponseIOQueue(
                request_responses_map
            )
            stack.enter_context(agent_io_queue)
            monkeypatch.setattr(
                client,
                "_send_request_message",
                agent_io_queue._send_request_message,
            )
            monkeypatch.setattr(
                client, "_get_response_pair", agent_io_queue._get_response_pair
            )
            yield monkeypatch, client

    @Parametrize.TRUNCATED_AGENT_RESPONSES
    def test_truncated_server_response(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        response: bytes,
    ) -> None:
        """Fail on truncated responses from the SSH agent."""
        del running_ssh_agent
        client = ssh_agent.SSHAgentClient()
        response_stream = io.BytesIO(response)

        class PseudoSocket:
            def sendall(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
                return None

            def recv(self, *args: Any, **kwargs: Any) -> Any:
                return response_stream.read(*args, **kwargs)

        pseudo_socket = PseudoSocket()
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(client, "_connection", pseudo_socket)
            with pytest.raises(EOFError):
                client.request(255, b"")

    @Parametrize.LIST_KEYS_ERROR_RESPONSES
    def test_list_keys_error_responses(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        response_code: _types.SSH_AGENT,
        response: bytes | bytearray,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
        """Fail on problems during key listing.

        Known problems:

          - The agent refuses, or otherwise indicates the operation
            failed.
          - The agent response is truncated.
          - The agent response is overlong.

        """
        del running_ssh_agent
        with self._setup_agent_and_request_handler({
            self.Request(_types.SSH_AGENTC.REQUEST_IDENTITIES, b""): [
                self.Response(response_code, response)
            ],
        }) as contexts:
            _, client = contexts
            with pytest.raises(exc_type, match=exc_pattern):
                client.list_keys()

    @Parametrize.SIGN_ERROR_RESPONSES
    def test_sign_error_responses(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        key: bytes | bytearray,
        check: bool,
        response_code: _types.SSH_AGENT,
        response: bytes | bytearray,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
        """Fail on problems during signing.

        Known problems:

          - The key is not loaded into the agent.
          - The agent refuses, or otherwise indicates the operation
            failed.

        """
        del running_ssh_agent
        Pair: TypeAlias = _types.SSHKeyCommentPair
        com = b"no comment"
        loaded_keys = [
            Pair(v.public_key_data, com).toreadonly()
            for v in data.SUPPORTED_KEYS.values()
        ]
        sign_payload = (
            ssh_agent.SSHAgentClient.string(key)
            + ssh_agent.SSHAgentClient.string(b"abc")
            + ssh_agent.SSHAgentClient.uint32(0)
        )
        with self._setup_agent_and_request_handler({
            self.Request(_types.SSH_AGENTC.SIGN_REQUEST, sign_payload): [
                self.Response(response_code, response)
            ],
        }) as contexts:
            monkeypatch, client = contexts
            monkeypatch.setattr(client, "list_keys", lambda: loaded_keys)
            with pytest.raises(exc_type, match=exc_pattern):
                client.sign(key, b"abc", check_if_key_loaded=check)

    @Parametrize.REQUEST_ERROR_RESPONSES
    def test_request_error_responses(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        request_code: _types.SSH_AGENTC,
        response_code: _types.SSH_AGENT,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
        """Fail on problems during signing.

        Known problems:

          - The key is not loaded into the agent.
          - The agent refuses, or otherwise indicates the operation
            failed.

        """
        del running_ssh_agent

        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            client = stack.enter_context(ssh_agent.SSHAgentClient())
            stack.enter_context(pytest.raises(exc_type, match=exc_pattern))
            client.request(request_code, b"", response_code=response_code)

    @Parametrize.QUERY_EXTENSIONS_MALFORMED_RESPONSES
    def test_query_extensions_malformed_responses(
        self,
        running_ssh_agent: data.RunningSSHAgentInfo,
        response_data: bytes,
    ) -> None:
        """Fail on malformed responses while querying extensions."""
        del running_ssh_agent
        with self._setup_agent_and_request_handler({
            self.Request(
                _types.SSH_AGENTC.EXTENSION,
                ssh_agent.SSHAgentClient.string(b"query"),
            ): [
                self.Response(
                    _types.SSH_AGENT.EXTENSION_RESPONSE, response_data
                )
            ],
        }) as contexts:
            _, client = contexts
            with pytest.raises(
                RuntimeError,
                match=r"Malformed response|does not match request",
            ):
                client.query_extensions()


class TestSSHAgentSocketProviderFailures:
    """Test SSH agent socket provider-specific failures."""

    def test_posix_provider_no_ssh_auth_sock(
        self,
        skip_if_no_af_unix_support: None,
    ) -> None:
        """For `posix`, fail if the running agent cannot be located."""
        del skip_if_no_af_unix_support
        provider = socketprovider.SocketProvider.resolve("posix")
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
            with pytest.raises(
                KeyError, match="SSH_AUTH_SOCK environment variable"
            ):
                provider()

    @pytest.mark.skipif(
        not hasattr(ctypes, "WinDLL"),
        reason="not relevant to systems without Windows named pipe support",
    )
    @hypothesis.given(named_pipe_name=Strategies.bad_named_pipe_names())
    def test_ssh_auth_sock_on_windows_provider_bad_named_pipe_name(
        self,
        named_pipe_name: str,
    ) -> None:
        """For `ssh_auth_sock_on_windows`, fail for bad named pipe names."""
        provider = socketprovider.SocketProvider.resolve(
            "ssh_auth_sock_on_windows"
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("SSH_AUTH_SOCK", named_pipe_name)
            with pytest.raises(ValueError, match="Invalid named pipe name"):
                provider()


class TestWindowsNamedPipeHandle:
    """Test the WindowsNamedPipeHandle wrapper class.

    Even works on other operating systems, because the relevant parts
    are stubbed out anyway.

    """

    DUMMY_ADDRESS = f"{socketprovider.PIPE_PREFIX}dummy-address"
    IO_ON_CLOSED_HANDLE_PATTERN = re.escape(
        socketprovider.WindowsNamedPipeHandle._IO_ON_CLOSED_FILE
    )

    @hypothesis.given(named_pipe_name=Strategies.bad_named_pipe_names())
    def test_constructor_bad_named_pipe_name(
        self,
        named_pipe_name: str,
    ) -> None:
        """The constructor fails for bad named pipe names."""
        with pytest.raises(ValueError, match="Invalid named pipe name"):  # noqa: SIM117
            with socketprovider.WindowsNamedPipeHandle(named_pipe_name):
                pass

    @contextlib.contextmanager
    def stub_createfile_and_closehandle(
        self,
    ) -> Iterator[None]:
        singleton = object()

        def create_file(*_args: Any, **_kwargs: Any) -> object:
            return singleton

        def close_handle(*_args: Any, **_kwargs: Any) -> bool:
            return True

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(socketprovider, "CreateFile", create_file)
            monkeypatch.setattr(socketprovider, "CloseHandle", close_handle)
            yield

    @Parametrize.IO_OPERATIONS_ON_HANDLES
    def test_closed_handle_cannot_be_operated_on(
        self,
        io_operation: Callable[[Any], Any],
    ) -> None:
        """Operating on a closed handle fails."""
        with self.stub_createfile_and_closehandle():
            handle = socketprovider.WindowsNamedPipeHandle(self.DUMMY_ADDRESS)
            with handle:
                pass  # close the handle
            with pytest.raises(
                ValueError, match=self.IO_ON_CLOSED_HANDLE_PATTERN
            ):
                io_operation(handle)

    @Parametrize.IO_OPERATIONS_ON_HANDLES
    def test_handle_is_non_reentrant(
        self,
        io_operation: Callable[[Any], Any],
    ) -> None:
        """The handler cannot be sensibly used in nested `with` blocks."""
        with self.stub_createfile_and_closehandle():
            handle = socketprovider.WindowsNamedPipeHandle(self.DUMMY_ADDRESS)
            with handle:
                with handle:
                    pass  # close the handle
                with pytest.raises(
                    ValueError, match=self.IO_ON_CLOSED_HANDLE_PATTERN
                ):
                    io_operation(handle)
