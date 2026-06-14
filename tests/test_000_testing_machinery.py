# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the test suite's data and machinery.

Currently, this entails testing [the SSH test keys][data.ALL_KEYS]
for internal consistency, and testing the functionality of the [stubbed
SSH agent][tests.machinery.StubbedSSHAgentSocket], in all variations.

"""

from __future__ import annotations

import base64
import contextlib
import errno
import os
import pathlib
import re
from typing import TYPE_CHECKING

import pytest

from derivepassphrase import _types, ssh_agent, vault
from tests import data, machinery

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Buffer

OPENSSH_MAGIC = b"openssh-key-v1\x00"
OPENSSH_HEADER = (
    OPENSSH_MAGIC  # magic
    + b"\x00\x00\x00\x04none"  # ciphername
    + b"\x00\x00\x00\x04none"  # kdfname
    + b"\x00\x00\x00\x00"  # kdfoptions
    + b"\x00\x00\x00\x01"  # number of keys
)
OPENSSH_NONE_CIPHER_BLOCKSIZE = 8


def as_openssh_keyfile_payload(
    public_key: bytes, private_key: bytes, checkint: int
) -> bytes:
    """Format an SSH private key in OpenSSH format.

    Args:
        public_key:
            The unframed public key, in SSH wire format.
        private_key:
            The unframed private key, in SSH wire format, including the
            comment.
        checkint:
            The "check" integer to use.

    Returns:
        The payload for a formatted OpenSSH private key, as a byte
        string, without the base64 encoding and the framing lines.

    """
    # The OpenSSH private key file format is described in PROTOCOL.key
    # in their git repository; see below for links to OpenSSH 10.0p2.
    # The block size of the "none" cipher is 8 bytes; see line 108 of
    # cipher.c, with definitions from line 67 onwards.  Padding is not
    # used if the payload already is a multiple of 8 bytes long; see
    # line 2935 onwards of sshkey.c
    #
    # https://github.com/openssh/openssh-portable/raw/2593769fb291fe6c542173927698c69e9f9a08b9/PROTOCOL.key
    # https://github.com/openssh/openssh-portable/raw/2593769fb291fe6c542173927698c69e9f9a08b9/cipher.c
    # https://github.com/openssh/openssh-portable/raw/2593769fb291fe6c542173927698c69e9f9a08b9/sshkey.c
    string = ssh_agent.SSHAgentClient.string
    uint32 = ssh_agent.SSHAgentClient.uint32
    payload = bytearray(OPENSSH_HEADER)
    payload.extend(string(public_key))
    secret = bytearray()
    secret.extend(uint32(checkint))  # checkint
    secret.extend(uint32(checkint))  # checkint
    secret.extend(private_key)  # privatekey1 and comment1
    i = 1
    while len(secret) % OPENSSH_NONE_CIPHER_BLOCKSIZE != 0:
        secret.append(i)
        i += 1
    payload.extend(string(secret))  # encrypted, padded list of private keys
    return bytes(payload)


def minimize_openssh_keyfile_padding(
    decoded_openssh_private_key: bytes,
) -> bytes:
    """Minimize the padding used in an OpenSSH private key file.

    Args:
        decoded_openssh_private_key:
            The non-base64-encoded, unframed, formatted OpenSSH private
            key.

    Returns:
        The same non-base64-encoded, unframed, formatted OpenSSH private
        key, but with minimal padding applied.

    """
    string = ssh_agent.SSHAgentClient.string
    unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix

    _public_key, framed_private_block = unstring_prefix(
        decoded_openssh_private_key.removeprefix(OPENSSH_HEADER)
    )
    result = bytearray(decoded_openssh_private_key).removesuffix(
        framed_private_block
    )
    private_block, trailer = unstring_prefix(framed_private_block)
    assert not trailer

    # Skip two checkint values.
    key_type, remainder = unstring_prefix(private_block[8:])
    # We need to semi-generically skip private key payloads.  Currently,
    # all supported (test) key types exclusively store multi-precision
    # integers or strings as their private key payload (which are both
    # parsed the same way, but interpreted differently).  We can
    # therefore generically parse `k` strings/mpints (for different
    # values of `k`, depending on key type) to correctly skip the
    # private key payload, and don't have to deal with having to parse
    # and skip other types of data such as uint32s.
    #
    # (This scheme needs updating if ever a different data type needs to
    # be parsed.)
    num_mpints = {
        b"ssh-ed25519": 2,
        b"ssh-ed448": 2,
        b"ssh-rsa": 6,
        b"ssh-dss": 5,
        b"ecdsa-sha2-nistp256": 3,
        b"ecdsa-sha2-nistp384": 3,
        b"ecdsa-sha2-nistp521": 3,
    }
    for _ in range(num_mpints[key_type]):
        _, remainder = unstring_prefix(remainder)
    # Skip comment.
    _comment, remainder = unstring_prefix(remainder)
    new_private_block = bytearray(private_block).removesuffix(remainder)
    padding = bytearray(remainder)

    expected_padding = bytearray()
    for i in range(1, len(padding) + 1):
        expected_padding.append(i & 0xFF)
    assert padding == expected_padding
    while len(padding) >= OPENSSH_NONE_CIPHER_BLOCKSIZE:
        padding[-OPENSSH_NONE_CIPHER_BLOCKSIZE:] = b""

    new_private_block.extend(padding)
    result.extend(string(new_private_block))
    return result


class Parametrize:
    """Common test parametrizations."""

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
    TEST_KEYS = pytest.mark.parametrize(
        ["keyname", "key"],
        data.ALL_KEYS.items(),
        ids=data.ALL_KEYS.keys(),
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
                            data.ALL_KEYS["rsa"].public_key_data
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
                            data.ALL_KEYS["ed25519"].public_key_data
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
                            data.ALL_KEYS["dsa1024"].public_key_data
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
    SUPPORTED_SSH_TEST_KEYS = pytest.mark.parametrize(
        ["ssh_test_key_type", "ssh_test_key"],
        list(data.SUPPORTED_KEYS.items()),
        ids=data.SUPPORTED_KEYS.keys(),
    )


class TestTestKeys:
    """Tests testing the test keys."""

    @Parametrize.TEST_KEYS
    def test_public_keys_are_internally_consistent(
        self,
        keyname: str,
        key: data.SSHTestKey,
    ) -> None:
        """The public key data structures are internally consistent."""
        del keyname
        string = ssh_agent.SSHAgentClient.string
        public_key_lines = key.public_key.splitlines(keepends=False)
        assert len(public_key_lines) == 1
        line_parts = public_key_lines[0].strip(b"\r\n").split(None, 2)
        key_type_name, public_key_b64 = line_parts[:2]
        assert base64.standard_b64encode(key.public_key_data) == public_key_b64
        assert key.public_key_data.startswith(string(key_type_name))

    @Parametrize.TEST_KEYS
    def test_private_keys_are_consistent_with_public_keys(
        self,
        keyname: str,
        key: data.SSHTestKey,
    ) -> None:
        """The private key data are consistent with their public parts."""
        del keyname
        string = ssh_agent.SSHAgentClient.string

        if key.public_key_data.startswith(string(b"ssh-rsa")):
            # RSA public keys are *not* prefixes of the corresponding
            # private key in OpenSSH format! RSA public keys consist of
            # an exponent e and a modulus n, which in the public key are
            # in the order (e, n), but in the order (n, e) in the
            # OpenSSH private key.  We thus need to parse and rearrange
            # the components of the public key into a new "mangled"
            # public key that then *is* a prefix of the respective
            # private key.
            unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
            key_type, numbers = unstring_prefix(key.public_key_data)
            e, encoded_n = unstring_prefix(numbers)
            n, trailer = unstring_prefix(encoded_n)
            assert not trailer
            mangled_public_key_data = string(key_type) + string(n) + string(e)
            assert (
                key.private_key_blob[: len(mangled_public_key_data)]
                == mangled_public_key_data
            )
        else:
            assert (
                key.private_key_blob[: len(key.public_key_data)]
                == key.public_key_data
            )

    @Parametrize.TEST_KEYS
    def test_private_keys_are_internally_consistent(
        self,
        keyname: str,
        key: data.SSHTestKey,
    ) -> None:
        """The private key data structures are internally consistent."""
        del keyname
        string = ssh_agent.SSHAgentClient.string

        private_key_lines = [
            line
            for line in key.private_key.splitlines(keepends=False)
            if line and not line.startswith((b"-----BEGIN", b"-----END"))
        ]
        private_key_from_openssh = base64.standard_b64decode(
            b"".join(private_key_lines)
        )
        wrapped_public_key = string(key.public_key_data)
        assert (
            private_key_from_openssh[
                len(OPENSSH_HEADER) : len(OPENSSH_HEADER)
                + len(wrapped_public_key)
            ]
            == wrapped_public_key
        )

        # Offset skips the header, the wrapped public key, and the
        # framing of the private keys section.
        offset = len(OPENSSH_HEADER) + len(wrapped_public_key) + 4
        checkint = int.from_bytes(
            private_key_from_openssh[offset : offset + 4], "big"
        )
        assert minimize_openssh_keyfile_padding(
            private_key_from_openssh
        ) == minimize_openssh_keyfile_padding(
            as_openssh_keyfile_payload(
                public_key=key.public_key_data,
                private_key=key.private_key_blob,
                checkint=checkint,
            )
        )


class TestStubbedSSHAgentSocketRequests:
    """Test the stubbed SSH agent socket: normal requests."""

    @contextlib.contextmanager
    def _get_addressed_agent(
        self, *, extended_agent: bool = False
    ) -> Iterator[machinery.StubbedSSHAgentSocketWithAddress]:
        agent_class: type[machinery.StubbedSSHAgentSocketWithAddress] = (
            machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA
            if extended_agent
            else machinery.StubbedSSHAgentSocketWithAddress
        )
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            monkeypatch.setenv("SSH_AUTH_SOCK", agent_class.ADDRESS)
            agent = stack.enter_context(agent_class())
            yield agent

    def test_query_extensions_base(self) -> None:
        """The base agent implements no extensions."""
        with self._get_addressed_agent(extended_agent=False) as agent:
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

    def test_query_extensions_extended(self) -> None:
        """The extended agent implements a known list of extensions."""
        with self._get_addressed_agent(extended_agent=True) as agent:
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

    def test_request_identities(self) -> None:
        """The agent implements a known list of identities."""
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        with machinery.StubbedSSHAgentSocket() as agent:
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
            assert orig_message[0] == _types.SSH_AGENT.IDENTITIES_ANSWER
            identity_count = int.from_bytes(orig_message[1:5], "big")
            message = bytes(orig_message[5:])
            for _ in range(identity_count):
                key, message = unstring_prefix(message)
                _comment, message = unstring_prefix(message)
                assert key
                assert key in {
                    k.public_key_data for k in data.ALL_KEYS.values()
                }
            assert not message

    def test_request_identities_extended(self) -> None:
        """The extended agent implements PuTTY's `list-extended` extension."""
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        with self._get_addressed_agent(extended_agent=True) as agent:
            extension_request = (
                # SSH string header
                b"\x00\x00\x00\x2e"
                # request code: SSH_AGENTC_REQUEST_IDENTITIES
                b"\x1b"
                # extension type: list-extended@putty.projects.tartarus.org
                b"\x00\x00\x00\x29list-extended@putty.projects.tartarus.org"
                # (no payload)
            )
            agent.sendall(extension_request)
            message_length = int.from_bytes(agent.recv(4), "big")
            orig_message: bytes | bytearray = bytearray(
                agent.recv(message_length)
            )
            assert orig_message[0] == _types.SSH_AGENT.SUCCESS
            identity_count = int.from_bytes(orig_message[1:5], "big")
            message = bytes(orig_message[5:])
            for _ in range(identity_count):
                key, message = unstring_prefix(message)
                _comment, message = unstring_prefix(message)
                flags, message = unstring_prefix(message)
                assert flags == b"\x00\x00\x00\x00"
                assert key
                assert key in {
                    k.public_key_data for k in data.ALL_KEYS.values()
                }
            assert not message

    @Parametrize.SUPPORTED_SSH_TEST_KEYS
    def test_sign(
        self,
        ssh_test_key_type: str,
        ssh_test_key: data.SSHTestKey,
    ) -> None:
        """The agent signs known key/message pairs."""
        del ssh_test_key_type
        spec = data.SSHTestKeyDeterministicSignatureClass.SPEC
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
        with machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(query_request)
            assert agent.recv(1000) == query_response


class TestStubbedSSHAgentSocketProperOperations:
    """Test the stubbed SSH agent socket: proper use and misuse."""

    def test_close_multiple(self) -> None:
        """The agent can be closed repeatedly."""
        with machinery.StubbedSSHAgentSocket() as agent:
            pass
        with machinery.StubbedSSHAgentSocket() as agent:
            pass
        del agent

    def test_closed_agents_cannot_be_interacted_with(self) -> None:
        """The agent can be closed repeatedly."""
        with machinery.StubbedSSHAgentSocket() as agent:
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
            match=re.escape(machinery.StubbedSSHAgentSocket._SOCKET_IS_CLOSED),
        ):
            agent.sendall(query_request)
        assert agent.recv(100) == query_response

    def test_no_recv_without_sendall(self) -> None:
        """The agent requires a message before sending a response."""
        with machinery.StubbedSSHAgentSocket() as agent:  # noqa: SIM117
            with pytest.raises(
                AssertionError,
                match=re.escape(
                    machinery.StubbedSSHAgentSocket._PROTOCOL_VIOLATION
                ),
            ):
                agent.recv(100)

    @Parametrize.INVALID_SSH_AGENT_MESSAGES
    def test_invalid_ssh_agent_messages(
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
        with machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(message)
            assert agent.recv(100) == query_response


class TestStubbedSSHAgentSocketSupportedAndUnsupportedFeatures:
    """Test the stubbed SSH agent socket: supported/unsupported features."""

    @Parametrize.UNSUPPORTED_SSH_AGENT_MESSAGES
    def test_unsupported_ssh_agent_messages(
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
        with machinery.StubbedSSHAgentSocket() as agent:
            agent.sendall(message)
            assert agent.recv(100) == query_response

    @Parametrize.STUBBED_AGENT_ADDRESSES
    def test_addresses(
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
            machinery.StubbedSSHAgentSocketWithAddress()
