# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test OpenSSH key loading and signing."""

from __future__ import annotations

import base64
import contextlib
import errno
import importlib.metadata
import io
import os
import pathlib
import re
import socket
import sys
import types
from typing import TYPE_CHECKING

import click
import click.testing
import hypothesis
import pytest
from hypothesis import stateful, strategies

import tests.data
import tests.data.callables
import tests.machinery
import tests.machinery.hypothesis
import tests.machinery.pytest
from derivepassphrase import _types, ssh_agent, vault
from derivepassphrase._internals import cli_helpers
from derivepassphrase.ssh_agent import socketprovider

if TYPE_CHECKING:
    from collections.abc import Iterable

    from typing_extensions import Any, Buffer, Literal

if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup


class Parametrize(types.SimpleNamespace):
    BAD_ENTRY_POINTS = pytest.mark.parametrize(
        "additional_entry_points",
        [
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=tests.data.faulty_entry_callable.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: faulty_entry_callable",
                    ),
                ],
                id="not-callable",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=tests.data.faulty_entry_name_exists.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: faulty_entry_name_exists",
                    ),
                ],
                id="name-already-exists",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=tests.data.faulty_entry_alias_exists.key,
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
                        name=tests.data.posix_entry.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: posix_entry",
                    ),
                    importlib.metadata.EntryPoint(
                        name=tests.data.the_annoying_os_entry.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data: the_annoying_os_entry",
                    ),
                ],
                id="existing-entries",
            ),
            pytest.param(
                [
                    importlib.metadata.EntryPoint(
                        name=tests.data.callables.provider_entry1.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data.callables: provider_entry1",
                    ),
                    importlib.metadata.EntryPoint(
                        name=tests.data.callables.provider_entry2.key,
                        group=socketprovider.SocketProvider.ENTRY_POINT_GROUP_NAME,
                        value="tests.data.callables: provider_entry2",
                    ),
                ],
                id="new-entries",
            ),
        ],
    )
    STUBBED_AGENT_ADDRESSES = pytest.mark.parametrize(
        ["address", "exception", "match"],
        [
            pytest.param(None, KeyError, "SSH_AUTH_SOCK", id="unset"),
            pytest.param("stub-ssh-agent:", None, "", id="standard"),
            pytest.param(
                str(pathlib.Path("~").expanduser()),
                FileNotFoundError,
                os.strerror(errno.ENOENT),
                id="invalid-url",
            ),
            pytest.param(
                "stub-ssh-agent:EPROTONOSUPPORT",
                OSError,
                os.strerror(errno.EPROTONOSUPPORT),
                id="protocol-not-supported",
            ),
            pytest.param(
                "stub-ssh-agent:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                OSError,
                os.strerror(errno.EINVAL),
                id="invalid-error-code",
            ),
        ],
    )
    EXISTING_REGISTRY_ENTRIES = pytest.mark.parametrize(
        "existing", ["posix", "the_annoying_os"]
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
                tests.data.SUPPORTED_KEYS["ed25519"].public_key_data,
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
            for value in tests.data.SUPPORTED_KEYS.values()
        ]
        + [(tests.data.callables.list_keys_singleton()[0].key, True)],
        ids=[*tests.data.SUPPORTED_KEYS.keys(), "singleton"],
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
    INVALID_SSH_AGENT_MESSAGES = pytest.mark.parametrize(
        "message",
        [
            pytest.param(b"\x00\x00\x00\x00", id="empty-message"),
            pytest.param(b"\x00\x00\x00\x0f\x0d", id="truncated-message"),
            pytest.param(
                b"\x00\x00\x00\x06\x1b\x00\x00\x00\x01\xff",
                id="invalid-extension-name",
            ),
            pytest.param(
                b"\x00\x00\x00\x11\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                id="sign-with-trailing-data",
            ),
        ],
    )
    UNSUPPORTED_SSH_AGENT_MESSAGES = pytest.mark.parametrize(
        "message",
        [
            pytest.param(
                ssh_agent.SSHAgentClient.string(
                    b"".join([
                        b"\x0d",
                        ssh_agent.SSHAgentClient.string(
                            tests.data.ALL_KEYS["rsa"].public_key_data
                        ),
                        ssh_agent.SSHAgentClient.string(vault.Vault.UUID),
                        b"\x00\x00\x00\x02",
                    ])
                ),
                id="sign-with-flags",
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(
                    b"".join([
                        b"\x0d",
                        ssh_agent.SSHAgentClient.string(
                            tests.data.ALL_KEYS["ed25519"].public_key_data
                        ),
                        b"\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07",
                        b"\x00\x00\x00\x00",
                    ])
                ),
                id="sign-with-nonstandard-passphrase",
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(
                    b"".join([
                        b"\x0d",
                        ssh_agent.SSHAgentClient.string(
                            tests.data.ALL_KEYS["dsa1024"].public_key_data
                        ),
                        ssh_agent.SSHAgentClient.string(vault.Vault.UUID),
                        b"\x00\x00\x00\x00",
                    ])
                ),
                id="sign-key-no-expected-signature",
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(
                    b"".join([
                        b"\x0d",
                        b"\x00\x00\x00\x00",
                        ssh_agent.SSHAgentClient.string(vault.Vault.UUID),
                        b"\x00\x00\x00\x00",
                    ])
                ),
                id="sign-key-unregistered-test-key",
            ),
        ],
    )
    PUBLIC_KEY_DATA = pytest.mark.parametrize(
        "public_key_struct",
        list(tests.data.SUPPORTED_KEYS.values()),
        ids=list(tests.data.SUPPORTED_KEYS.keys()),
    )
    REQUEST_ERROR_RESPONSES = pytest.mark.parametrize(
        ["request_code", "response_code", "exc_type", "exc_pattern"],
        [
            pytest.param(
                _types.SSH_AGENTC.REQUEST_IDENTITIES,
                _types.SSH_AGENT.SUCCESS,
                ssh_agent.SSHAgentFailedError,
                re.escape(
                    f"[Code {_types.SSH_AGENT.IDENTITIES_ANSWER.value}]"
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
    SUPPORTED_SSH_TEST_KEYS = pytest.mark.parametrize(
        ["ssh_test_key_type", "ssh_test_key"],
        list(tests.data.SUPPORTED_KEYS.items()),
        ids=tests.data.SUPPORTED_KEYS.keys(),
    )
    UNSUITABLE_SSH_TEST_KEYS = pytest.mark.parametrize(
        ["ssh_test_key_type", "ssh_test_key"],
        list(tests.data.UNSUITABLE_KEYS.items()),
        ids=tests.data.UNSUITABLE_KEYS.keys(),
    )
    RESOLVE_CHAINS = pytest.mark.parametrize(
        ["terminal", "chain"],
        [
            pytest.param("callable", ["a"], id="callable-1"),
            pytest.param("callable", ["a", "b", "c", "d"], id="callable-4"),
            pytest.param("alias", ["e"], id="alias-5"),
            pytest.param("alias", ["e", "f", "g", "h", "i"], id="alias-5"),
            pytest.param("unimplemented", ["j"], id="unimplemented-1"),
            pytest.param("unimplemented", ["j", "k"], id="unimplemented-2"),
        ],
    )


class TestTestingMachineryStubbedSSHAgentSocket:
    """Test the stubbed SSH agent socket for the `ssh_agent` module tests."""

    def test_100a_query_extensions_base(self) -> None:
        """The base agent implements no extensions."""
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            monkeypatch.setenv(
                "SSH_AUTH_SOCK", tests.machinery.StubbedSSHAgentSocketWithAddress.ADDRESS
            )
            agent = stack.enter_context(
                tests.machinery.StubbedSSHAgentSocketWithAddress()
            )
            assert "query" not in agent.enabled_extensions
            query_request = (
                # SSH string header
                b"\x00\x00\x00\x0a"
                # request code: SSH_AGENTC_EXTENSION
                b"\x1b"
                # payload: SSH string "query"
                b"\x00\x00\x00\x05query"
            )
            query_response = (
                # SSH string header
                b"\x00\x00\x00\x01"
                # response code: SSH_AGENT_FAILURE
                b"\x05"
            )
            agent.sendall(query_request)
            assert agent.recv(1000) == query_response

    def test_100b_query_extensions_extended(self) -> None:
        """The extended agent implements a known list of extensions."""
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            monkeypatch.setenv(
                "SSH_AUTH_SOCK", tests.machinery.StubbedSSHAgentSocketWithAddress.ADDRESS
            )
            agent = stack.enter_context(
                tests.machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA()
            )
            assert "query" in agent.enabled_extensions
            query_request = (
                # SSH string header
                b"\x00\x00\x00\x0a"
                # request code: SSH_AGENTC_EXTENSION
                b"\x1b"
                # payload: SSH string "query"
                b"\x00\x00\x00\x05query"
            )
            query_response = (
                # SSH string header
                b"\x00\x00\x00\x40"
                # response code: SSH_AGENT_EXTENSION_RESPONSE
                b"\x1d"
                # extension response: extension type ("query")
                b"\x00\x00\x00\x05query"
                # supported extension #1: query
                b"\x00\x00\x00\x05query"
                # supported extension #2:
                # list-extended@putty.projects.tartarus.org
                b"\x00\x00\x00\x29list-extended@putty.projects.tartarus.org"
            )
            agent.sendall(query_request)
            assert agent.recv(1000) == query_response

    def test_101_request_identities(self) -> None:
        """The agent implements a known list of identities."""
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            query_request = (
                # SSH string header
                b"\x00\x00\x00\x01"
                # request code: SSH_AGENTC_REQUEST_IDENTITIES
                b"\x0b"
            )
            agent.sendall(query_request)
            message_length = int.from_bytes(agent.recv(4), "big")
            orig_message: bytes | bytearray = bytearray(
                agent.recv(message_length)
            )
            assert (
                _types.SSH_AGENT(orig_message[0])
                == _types.SSH_AGENT.IDENTITIES_ANSWER
            )
            identity_count = int.from_bytes(orig_message[1:5], "big")
            message = bytes(orig_message[5:])
            for _ in range(identity_count):
                key, message = unstring_prefix(message)
                _comment, message = unstring_prefix(message)
                assert key
                assert key in {
                    k.public_key_data for k in tests.data.ALL_KEYS.values()
                }
            assert not message

    @Parametrize.SUPPORTED_SSH_TEST_KEYS
    def test_102_sign(
        self,
        ssh_test_key_type: str,
        ssh_test_key: tests.data.SSHTestKey,
    ) -> None:
        """The agent signs known key/message pairs."""
        del ssh_test_key_type
        spec = tests.data.SSHTestKeyDeterministicSignatureClass.SPEC
        assert ssh_test_key.expected_signatures[spec].signature is not None
        string = ssh_agent.SSHAgentClient.string
        query_request = string(
            # request code: SSH_AGENTC_SIGN_REQUEST
            b"\x0d"
            # key: SSH string of the public key
            + string(ssh_test_key.public_key_data)
            # payload: SSH string of the vault UUID
            + string(vault.Vault.UUID)
            # signing flags (uint32, empty)
            + b"\x00\x00\x00\x00"
        )
        query_response = string(
            # response code: SSH_AGENT_SIGN_RESPONSE
            b"\x0e"
            # expected payload: the binary signature as recorded in the test key data structure
            + string(ssh_test_key.expected_signatures[spec].signature)
        )
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(query_request)
            assert agent.recv(1000) == query_response

    def test_120_close_multiple(self) -> None:
        """The agent can be closed repeatedly."""
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            pass
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            pass
        del agent

    def test_121_closed_agents_cannot_be_interacted_with(self) -> None:
        """The agent can be closed repeatedly."""
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            pass
        query_request = (
            # SSH string header
            b"\x00\x00\x00\x0a"
            # request code: SSH_AGENTC_EXTENSION
            b"\x1b"
            # payload: SSH string "query"
            b"\x00\x00\x00\x05query"
        )
        query_response = b""
        with pytest.raises(
            ValueError,
            match=re.escape(tests.machinery.StubbedSSHAgentSocket._SOCKET_IS_CLOSED),
        ):
            agent.sendall(query_request)
        assert agent.recv(100) == query_response

    def test_122_no_recv_without_sendall(self) -> None:
        """The agent requires a message before sending a response."""
        with tests.machinery.StubbedSSHAgentSocket() as agent:  # noqa: SIM117
            with pytest.raises(
                AssertionError,
                match=re.escape(
                    tests.machinery.StubbedSSHAgentSocket._PROTOCOL_VIOLATION
                ),
            ):
                agent.recv(100)

    @Parametrize.INVALID_SSH_AGENT_MESSAGES
    def test_123_invalid_ssh_agent_messages(
        self,
        message: Buffer,
    ) -> None:
        """The agent responds with errors on invalid messages."""
        query_response = (
            # SSH string header
            b"\x00\x00\x00\x01"
            # response code: SSH_AGENT_FAILURE
            b"\x05"
        )
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(message)
            assert agent.recv(100) == query_response

    @Parametrize.UNSUPPORTED_SSH_AGENT_MESSAGES
    def test_124_unsupported_ssh_agent_messages(
        self,
        message: Buffer,
    ) -> None:
        """The agent responds with errors on unsupported messages."""
        query_response = (
            # SSH string header
            b"\x00\x00\x00\x01"
            # response code: SSH_AGENT_FAILURE
            b"\x05"
        )
        with tests.machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(message)
            assert agent.recv(100) == query_response

    @Parametrize.STUBBED_AGENT_ADDRESSES
    def test_125_addresses(
        self,
        address: str | None,
        exception: type[Exception] | None,
        match: str,
    ) -> None:
        """The agent accepts addresses."""
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            if address:
                monkeypatch.setenv("SSH_AUTH_SOCK", address)
            else:
                monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
            if exception:
                stack.enter_context(
                    pytest.raises(exception, match=re.escape(match))
                )
            tests.machinery.StubbedSSHAgentSocketWithAddress()


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

    # TODO(the-13th-letter): Re-evaluate if this check is worth keeping.
    # It cannot provide true tamper-resistence, but probably appears to.
    @Parametrize.PUBLIC_KEY_DATA
    def test_100_key_decoding(
        self,
        public_key_struct: tests.data.SSHTestKey,
    ) -> None:
        """The [`tests.ALL_KEYS`][] public key data looks sane."""
        keydata = base64.b64decode(
            public_key_struct.public_key.split(None, 2)[1]
        )
        assert keydata == public_key_struct.public_key_data, (
            "recorded public key data doesn't match"
        )

    @Parametrize.SH_EXPORT_LINES
    def test_190_sh_export_line_parsing(
        self, line: str, env_name: str, value: str | None
    ) -> None:
        """[`tests.parse_sh_export_line`][] works."""
        if value is not None:
            assert tests.data.callables.parse_sh_export_line(line, env_name=env_name) == value
        else:
            with pytest.raises(ValueError, match="Cannot parse sh line:"):
                tests.data.callables.parse_sh_export_line(line, env_name=env_name)

    def test_200_constructor_posix_no_ssh_auth_sock(
        self,
        skip_if_no_af_unix_support: None,
    ) -> None:
        """Abort if the running agent cannot be located on POSIX."""
        del skip_if_no_af_unix_support
        posix_handler = socketprovider.SocketProvider.resolve("posix")
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
            with pytest.raises(
                KeyError, match="SSH_AUTH_SOCK environment variable"
            ):
                posix_handler()

    @Parametrize.UINT32_INPUT
    def test_210_uint32(self, input: int, expected: bytes | bytearray) -> None:
        """`uint32` encoding works."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert uint32(input) == expected

    @hypothesis.given(strategies.integers(min_value=0, max_value=0xFFFFFFFF))
    @hypothesis.example(0xDEADBEEF).via("manual, pre-hypothesis example")
    def test_210a_uint32_from_number(self, num: int) -> None:
        """`uint32` encoding works, starting from numbers."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert int.from_bytes(uint32(num), "big", signed=False) == num

    @hypothesis.given(strategies.binary(min_size=4, max_size=4))
    @hypothesis.example(b"\xde\xad\xbe\xef").via(
        "manual, pre-hypothesis example"
    )
    def test_210b_uint32_from_bytestring(self, bytestring: bytes) -> None:
        """`uint32` encoding works, starting from length four byte strings."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert (
            uint32(int.from_bytes(bytestring, "big", signed=False))
            == bytestring
        )

    @Parametrize.SSH_STRING_INPUT
    def test_211_string(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        """SSH string encoding works."""
        string = ssh_agent.SSHAgentClient.string
        assert bytes(string(input)) == expected

    @hypothesis.given(strategies.binary(max_size=0x0001FFFF))
    @hypothesis.example(b"DEADBEEF" * 10000).via(
        "manual, pre-hypothesis example with highest order bit set"
    )
    def test_211a_string_from_bytestring(self, bytestring: bytes) -> None:
        """SSH string encoding works, starting from a byte string."""
        res = ssh_agent.SSHAgentClient.string(bytestring)
        assert res.startswith((b"\x00\x00", b"\x00\x01"))
        assert int.from_bytes(res[:4], "big", signed=False) == len(bytestring)
        assert res[4:] == bytestring

    @Parametrize.SSH_UNSTRING_INPUT
    def test_212_unstring(
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
    def test_212a_unstring_of_string_of_data(self, bytestring: bytes) -> None:
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
    def test_212b_string_of_unstring_of_data(self, encoded: bytes) -> None:
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

    def test_220_registry_resolve(
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
    def test_221_registry_resolve_chains(
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
    def test_221a_registry_resolve_chains(
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
    def test_230_find_all_socket_providers(
        self,
        additional_entry_points: list[importlib.metadata.EntryPoint],
    ) -> None:
        """Finding all SSH agent socket providers works."""
        resolve = socketprovider.SocketProvider.resolve
        old_registry = socketprovider.SocketProvider.registry
        with tests.machinery.pytest.faked_entry_point_list(
            additional_entry_points, remove_conflicting_entries=False
        ) as names:
            socketprovider.SocketProvider._find_all_ssh_agent_socket_providers()
            for name in names:
                assert name in socketprovider.SocketProvider.registry
                assert resolve(name) in {
                    tests.data.callables.provider_entry_provider,
                    *old_registry.values(),
                }

    @Parametrize.BAD_ENTRY_POINTS
    def test_231_find_all_socket_providers_errors(
        self,
        additional_entry_points: list[importlib.metadata.EntryPoint],
    ) -> None:
        """Finding faulty SSH agent socket providers raises errors."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                tests.machinery.pytest.faked_entry_point_list(
                    additional_entry_points, remove_conflicting_entries=False
                )
            )
            stack.enter_context(pytest.raises(AssertionError))
            socketprovider.SocketProvider._find_all_ssh_agent_socket_providers()

    @Parametrize.UINT32_EXCEPTIONS
    def test_310_uint32_exceptions(
        self, input: int, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """`uint32` encoding fails for out-of-bound values."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        with pytest.raises(exc_type, match=exc_pattern):
            uint32(input)

    @Parametrize.SSH_STRING_EXCEPTIONS
    def test_311_string_exceptions(
        self, input: Any, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """SSH string encoding fails for non-strings."""
        string = ssh_agent.SSHAgentClient.string
        with pytest.raises(exc_type, match=exc_pattern):
            string(input)

    @Parametrize.SSH_UNSTRING_EXCEPTIONS
    def test_312_unstring_exceptions(
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

    def test_320_registry_already_registered(
        self,
    ) -> None:
        """The registry forbids overwriting entries."""
        registry = socketprovider.SocketProvider.registry.copy()
        resolve = socketprovider.SocketProvider.resolve
        register = socketprovider.SocketProvider.register
        the_annoying_os = resolve("the_annoying_os")
        posix = resolve("posix")
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", registry
            )
            register("posix")(posix)
            register("the_annoying_os")(the_annoying_os)
            with pytest.raises(ValueError, match="already registered"):
                register("posix")(the_annoying_os)
            with pytest.raises(ValueError, match="already registered"):
                register("the_annoying_os")(posix)
            with pytest.raises(ValueError, match="already registered"):
                register("posix", "the_annoying_os_named_pipe")(posix)
            with pytest.raises(ValueError, match="already registered"):
                register("the_annoying_os", "unix_domain")(the_annoying_os)

    def test_321_registry_resolve_non_existant_entries(
        self,
    ) -> None:
        """Resolving a non-existant entry fails."""
        new_registry = {
            "posix": socketprovider.SocketProvider.registry["posix"],
            "the_annoying_os": socketprovider.SocketProvider.registry[
                "the_annoying_os"
            ],
        }
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                socketprovider.SocketProvider, "registry", new_registry
            )
            with pytest.raises(socketprovider.NoSuchProviderError):
                socketprovider.SocketProvider.resolve("native")

    def test_322_registry_register_new_entry(
        self,
    ) -> None:
        """Registering new entries works."""

        def socket_provider() -> _types.SSHAgentSocket:
            raise AssertionError

        names = ["spam", "ham", "eggs", "parrot"]
        new_registry = {
            "posix": socketprovider.SocketProvider.registry["posix"],
            "the_annoying_os": socketprovider.SocketProvider.registry[
                "the_annoying_os"
            ],
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
    def test_323_registry_register_old_entry(
        self,
        existing: str,
    ) -> None:
        """Registering old entries works."""

        provider = socketprovider.SocketProvider.resolve(existing)
        new_registry = {
            "posix": socketprovider.SocketProvider.registry["posix"],
            "the_annoying_os": socketprovider.SocketProvider.registry[
                "the_annoying_os"
            ],
            "unix_domain": "posix",
            "the_annoying_os_named_pipe": "the_annoying_os",
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
            assert not all(
                map(socketprovider.SocketProvider.registry.__contains__, names)
            )
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


class TestAgentInteraction:
    """Test actually talking to the SSH agent."""

    @Parametrize.SUPPORTED_SSH_TEST_KEYS
    def test_200_sign_data_via_agent(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        ssh_test_key_type: str,
        ssh_test_key: tests.data.SSHTestKey,
    ) -> None:
        """Signing data with specific SSH keys works.

        Single tests may abort early (skip) if the indicated key is not
        loaded in the agent.  Presumably this means the key type is
        unsupported.

        """
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = ssh_test_key.public_key_data
        assert (
            tests.data.SSHTestKeyDeterministicSignatureClass.SPEC
            in ssh_test_key.expected_signatures
        )
        sig = ssh_test_key.expected_signatures[
            tests.data.SSHTestKeyDeterministicSignatureClass.SPEC
        ]
        expected_signature = sig.signature
        derived_passphrase = sig.derived_passphrase
        if public_key_data not in key_comment_pairs:  # pragma: no cover
            pytest.skip(f"prerequisite {ssh_test_key_type} SSH key not loaded")
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

    @Parametrize.UNSUITABLE_SSH_TEST_KEYS
    def test_201_sign_data_via_agent_unsupported(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        ssh_test_key_type: str,
        ssh_test_key: tests.data.SSHTestKey,
    ) -> None:
        """Using an unsuitable key with [`vault.Vault`][] fails.

        Single tests may abort early (skip) if the indicated key is not
        loaded in the agent.  Presumably this means the key type is
        unsupported.  Single tests may also abort early if the agent
        ensures that the generally unsuitable key is actually suitable
        under this agent.

        """
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = ssh_test_key.public_key_data
        if public_key_data not in key_comment_pairs:  # pragma: no cover
            pytest.skip(f"prerequisite {ssh_test_key_type} SSH key not loaded")
        assert not vault.Vault.is_suitable_ssh_key(
            public_key_data, client=None
        ), f"Expected {ssh_test_key_type} key to be unsuitable in general"
        if vault.Vault.is_suitable_ssh_key(public_key_data, client=client):
            pytest.skip(
                f"agent automatically ensures {ssh_test_key_type} key is suitable"
            )
        with pytest.raises(ValueError, match="unsuitable SSH key"):
            vault.Vault.phrase_from_key(public_key_data, conn=client)

    @Parametrize.SSH_KEY_SELECTION
    def test_210_ssh_key_selector(
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

        def key_is_suitable(key: bytes) -> bool:
            """Stub out [`vault.Vault.key_is_suitable`][]."""
            always = {v.public_key_data for v in tests.data.SUPPORTED_KEYS.values()}
            dsa = {
                v.public_key_data
                for k, v in tests.data.UNSUITABLE_KEYS.items()
                if k.startswith(("dsa", "ecdsa"))
            }
            return key in always or (
                client.has_deterministic_dsa_signatures() and key in dsa
            )

        # TODO(the-13th-letter): Handle the unlikely(?) case that only
        # one test key is loaded, but `single` is False.  Rename the
        # `index` variable to `input`, store the `input` in there, and
        # make the definition of `text` in the else block dependent on
        # `n` being singular or non-singular.
        if single:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient,
                "list_keys",
                tests.data.callables.list_keys_singleton,
            )
            keys = [
                pair.key
                for pair in tests.data.callables.list_keys_singleton()
                if key_is_suitable(pair.key)
            ]
            index = "1"
            text = "Use this key? yes\n"
        else:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, "list_keys", tests.data.callables.list_keys
            )
            keys = [
                pair.key
                for pair in tests.data.callables.list_keys()
                if key_is_suitable(pair.key)
            ]
            index = str(1 + keys.index(key))
            n = len(keys)
            text = f"Your selection? (1-{n}, leave empty to abort): {index}\n"
        b64_key = base64.standard_b64encode(key).decode("ASCII")

        @click.command()
        def driver() -> None:
            """Call [`cli_helpers.select_ssh_key`][] directly, as a command."""
            key = cli_helpers.select_ssh_key(client)
            click.echo(base64.standard_b64encode(key).decode("ASCII"))

        # TODO(the-13th-letter): (Continued from above.)  Update input
        # data to use `index`/`input` directly and unconditionally.
        runner = tests.machinery.CliRunner(mix_stderr=True)
        result = runner.invoke(
            driver,
            [],
            input=("yes\n" if single else f"{index}\n"),
            catch_exceptions=True,
        )
        for snippet in ("Suitable SSH keys:\n", text, f"\n{b64_key}\n"):
            assert result.clean_exit(output=snippet), "expected clean exit"

    def test_300_constructor_bad_running_agent(
        self,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
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

    def test_301_constructor_no_af_unix_support(self) -> None:
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

    def test_302_no_ssh_agent_socket_provider_available(
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

    def test_303_explicit_socket(
        self,
        spawn_ssh_agent: tests.data.SpawnedSSHAgentInfo,
    ) -> None:
        conn = spawn_ssh_agent.client._connection
        ssh_agent.SSHAgentClient(socket=conn)

    @Parametrize.TRUNCATED_AGENT_RESPONSES
    def test_310_truncated_server_response(
        self,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
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
    def test_320_list_keys_error_responses(
        self,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
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

        passed_response_code = response_code

        # TODO(the-13th-letter): Extract this mock function into a common
        # top-level "request" mock function.
        def request(
            request_code: int | _types.SSH_AGENTC,
            payload: bytes | bytearray,
            /,
            *,
            response_code: Iterable[int | _types.SSH_AGENT]
            | int
            | _types.SSH_AGENT
            | None = None,
        ) -> tuple[int, bytes | bytearray] | bytes | bytearray:
            del request_code
            del payload
            if isinstance(  # pragma: no branch
                response_code, (int, _types.SSH_AGENT)
            ):
                response_code = frozenset({response_code})
            if response_code is not None:  # pragma: no branch
                response_code = frozenset({
                    c if isinstance(c, int) else c.value for c in response_code
                })

            if not response_code:  # pragma: no cover
                return (passed_response_code.value, response)
            if passed_response_code.value not in response_code:
                raise ssh_agent.SSHAgentFailedError(
                    passed_response_code.value, response
                )
            return response

        with pytest.MonkeyPatch.context() as monkeypatch:
            client = ssh_agent.SSHAgentClient()
            monkeypatch.setattr(client, "request", request)
            with pytest.raises(exc_type, match=exc_pattern):
                client.list_keys()

    @Parametrize.SIGN_ERROR_RESPONSES
    def test_330_sign_error_responses(
        self,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
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
        passed_response_code = response_code

        # TODO(the-13th-letter): Extract this mock function into a common
        # top-level "request" mock function.
        def request(
            request_code: int | _types.SSH_AGENTC,
            payload: bytes | bytearray,
            /,
            *,
            response_code: Iterable[int | _types.SSH_AGENT]
            | int
            | _types.SSH_AGENT
            | None = None,
        ) -> tuple[int, bytes | bytearray] | bytes | bytearray:
            del request_code
            del payload
            if isinstance(  # pragma: no branch
                response_code, (int, _types.SSH_AGENT)
            ):
                response_code = frozenset({response_code})
            if response_code is not None:  # pragma: no branch
                response_code = frozenset({
                    c if isinstance(c, int) else c.value for c in response_code
                })

            if not response_code:  # pragma: no cover
                return (passed_response_code.value, response)
            if (
                passed_response_code.value not in response_code
            ):  # pragma: no branch
                raise ssh_agent.SSHAgentFailedError(
                    passed_response_code.value, response
                )
            return response  # pragma: no cover

        with pytest.MonkeyPatch.context() as monkeypatch:
            client = ssh_agent.SSHAgentClient()
            monkeypatch.setattr(client, "request", request)
            Pair = _types.SSHKeyCommentPair  # noqa: N806
            com = b"no comment"
            loaded_keys = [
                Pair(v.public_key_data, com).toreadonly()
                for v in tests.data.SUPPORTED_KEYS.values()
            ]
            monkeypatch.setattr(client, "list_keys", lambda: loaded_keys)
            with pytest.raises(exc_type, match=exc_pattern):
                client.sign(key, b"abc", check_if_key_loaded=check)

    @Parametrize.REQUEST_ERROR_RESPONSES
    def test_340_request_error_responses(
        self,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
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
            stack.enter_context(pytest.raises(exc_type, match=exc_pattern))
            client = stack.enter_context(ssh_agent.SSHAgentClient())
            client.request(request_code, b"", response_code=response_code)

    @Parametrize.QUERY_EXTENSIONS_MALFORMED_RESPONSES
    def test_350_query_extensions_malformed_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.data.RunningSSHAgentInfo,
        response_data: bytes,
    ) -> None:
        """Fail on malformed responses while querying extensions."""
        del running_ssh_agent

        # TODO(the-13th-letter): Extract this mock function into a common
        # top-level "request" mock function after removing the
        # payload-specific parts.
        def request(
            code: int | _types.SSH_AGENTC,
            payload: Buffer,
            /,
            *,
            response_code: (
                Iterable[_types.SSH_AGENT | int]
                | _types.SSH_AGENT
                | int
                | None
            ) = None,
        ) -> tuple[int, bytes] | bytes:
            request_codes = {
                _types.SSH_AGENTC.EXTENSION,
                _types.SSH_AGENTC.EXTENSION.value,
            }
            assert code in request_codes
            response_codes = {
                _types.SSH_AGENT.EXTENSION_RESPONSE,
                _types.SSH_AGENT.EXTENSION_RESPONSE.value,
                _types.SSH_AGENT.SUCCESS,
                _types.SSH_AGENT.SUCCESS.value,
            }
            assert payload == b"\x00\x00\x00\x05query"
            if response_code is None:  # pragma: no cover
                return (
                    _types.SSH_AGENT.EXTENSION_RESPONSE.value,
                    response_data,
                )
            if isinstance(  # pragma: no cover
                response_code, (_types.SSH_AGENT, int)
            ):
                assert response_code in response_codes
                return response_data
            for single_code in response_code:  # pragma: no cover
                assert single_code in response_codes
            return response_data  # pragma: no cover

        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch2 = stack.enter_context(monkeypatch.context())
            client = stack.enter_context(ssh_agent.SSHAgentClient())
            monkeypatch2.setattr(client, "request", request)
            with pytest.raises(
                RuntimeError,
                match=r"Malformed response|does not match request",
            ):
                client.query_extensions()


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

    size = draw(chain_size)
    if size < 1:  # pragma: no cover
        raise ValueError(err_msg_chain_size)
    names: list[str] = []
    base: str | None = None
    if existing:
        names.append(draw(known_keys_strategy.filter(not_an_alias)))
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
    names.extend(draw(list_strategy))
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
            "posix": self.orig_registry["posix"],
            "the_annoying_os": self.orig_registry["the_annoying_os"],
            "native": self.orig_registry["native"],
            "unix_domain": "posix",
            "the_annoying_os_named_pipe": "the_annoying_os",
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
