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
import math
import os
import pathlib
import re
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import _types, ssh_agent, vault
from tests import data, machinery

if TYPE_CHECKING:
    from collections.abc import Generator

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
    return bytes(result)


class Parametrize:
    """Common test parametrizations."""

    LIST_IDENTITIES = pytest.mark.parametrize(
        ["extended_agent", "query_request"],
        [
            pytest.param(
                None,
                (
                    # SSH string header
                    b"\x00\x00\x00\x01"
                    # request code: SSH_AGENTC_REQUEST_IDENTITIES
                    b"\x0b"
                ),
                id="base",
            ),
            pytest.param(
                True,
                (
                    # SSH string header
                    b"\x00\x00\x00\x2e"
                    # request code: SSH_AGENTC_REQUEST_IDENTITIES
                    b"\x1b"
                    # extension type: list-extended@putty.projects.tartarus.org
                    b"\x00\x00\x00\x29list-extended@putty.projects.tartarus.org"
                    # (no payload)
                ),
                id="extended",
            ),
        ],
    )
    QUERY_EXTENSION = pytest.mark.parametrize(
        ["extended_agent", "query_response"],
        [
            pytest.param(
                None,
                (
                    # SSH string header
                    b"\x00\x00\x00\x01"
                    # response code: SSH_AGENT_FAILURE
                    b"\x05"
                ),
                id="base",
            ),
            pytest.param(
                True,
                (
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
                ),
                id="extended",
            ),
        ],
    )
    TEST_KEYS = pytest.mark.parametrize(
        ["keyname", "key"],
        data.ALL_KEYS.items(),
        ids=data.ALL_KEYS.keys(),
    )
    SUPPORTED_SSH_TEST_KEYS = pytest.mark.parametrize(
        ["ssh_test_key_type", "ssh_test_key", "requires_deterministic_dsa"],
        [(k, v, False) for k, v in data.SUPPORTED_KEYS.items()]
        + [(k, v, True) for k, v in data.CONDITIONALLY_SUPPORTED_KEYS.items()],
        ids=list(data.SUPPORTED_KEYS.keys())
        + list(data.CONDITIONALLY_SUPPORTED_KEYS.keys()),
    )


class Strategies:
    """Common hypothesis data generation strategies."""

    @strategies.composite
    @staticmethod
    def proper_bytestring_partition(
        draw: strategies.DrawFn, bs: bytes | bytearray, /
    ) -> list[bytes]:
        """Partition a non-empty string into non-empty parts.

        A string of length `n` is partitioned [`math.isqrt(n
        - 1)`][math.isqrt] many times, such that each substring is
        non-empty.

        """
        n = len(bs)
        hypothesis.assume(n > 0)
        num_divisions = math.isqrt(n - 1)
        divisions = draw(
            strategies.lists(
                strategies.integers(1, n - 1),
                min_size=num_divisions,
                max_size=num_divisions,
                unique=True,
            ).map(sorted),
            label="divisions",
        )
        result: list[bytes] = []
        i = 0
        for div in divisions:
            result.append(bytes(bs[i:div]))
            i = div
        result.append(bytes(bs[i:n]))
        return result

    @strategies.composite
    @staticmethod
    def truncated_agent_request(
        draw: strategies.DrawFn, /, min_size: int = 0, max_size: int = 100
    ) -> bytes:
        """Generate a private-use SSH agent request with truncated payload.

        The message will adhere to specified size bounds before
        truncation.  The request message code will be from the private
        use area.

        Args:
            min_size:
                The minimum size of the request payload, after truncation.
            max_size:
                The maximum size of the request payload, before truncation.

        """
        request_code = draw(
            strategies.integers(240, 255), label="request_code"
        )
        full_message_size = draw(
            strategies.integers(min_size + 1, max_size),
            label="full_message_size",
        )
        truncated_message = draw(
            strategies.binary(
                min_size=min_size, max_size=full_message_size - 1
            )
        )
        payload = bytearray(
            int.to_bytes(1 + full_message_size, 4, "big", signed=False)
        )
        payload.extend(int.to_bytes(request_code, 1, "big", signed=False))
        payload.extend(truncated_message)
        return bytes(payload)

    @staticmethod
    def invalid_ssh_agent_messages() -> strategies.SearchStrategy[bytes]:
        """Generate invalid agent request messages."""
        string = ssh_agent.SSHAgentClient.string
        empty_message = [b""]
        invalid_extension_name = [b"\x1b", b"\x00\x00\x00\x01\xff"]
        sign_with_trailing_data = [
            b"\x0d",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
        ]
        sign_without_payload = [b"\x0d", b"\x00\x00\x00\x00"]
        return (
            strategies
            .sampled_from([
                empty_message,
                invalid_extension_name,
                sign_with_trailing_data,
                sign_without_payload,
            ])
            .map(b"".join)
            .map(string)
        )

    @staticmethod
    def unsupported_ssh_agent_messages() -> strategies.SearchStrategy[bytes]:
        """Generate agent request messages unsupported by the stubbed agent."""
        string = ssh_agent.SSHAgentClient.string
        sign_with_flags = [
            b"\x0d",
            string(data.ALL_KEYS["rsa"].public_key_data),
            string(vault.Vault.UUID),
            b"\x00\x00\x00\x02",
        ]
        sign_with_nonstandard_passphrase = [
            b"\x0d",
            string(data.ALL_KEYS["ed25519"].public_key_data),
            b"\x00\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07",
            b"\x00\x00\x00\x00",
        ]
        # NOTE: only unsupported when stubbed agent has RFC 6979 support
        # disabled
        sign_key_no_expected_signature = [
            b"\x0d",
            string(data.ALL_KEYS["dsa1024"].public_key_data),
            string(vault.Vault.UUID),
            b"\x00\x00\x00\x00",
        ]
        sign_key_unregistered_test_key = [
            b"\x0d",
            b"\x00\x00\x00\x00",
            string(vault.Vault.UUID),
            b"\x00\x00\x00\x00",
        ]
        return (
            strategies
            .sampled_from([
                sign_with_flags,
                sign_with_nonstandard_passphrase,
                sign_key_no_expected_signature,
                sign_key_unregistered_test_key,
            ])
            .map(b"".join)
            .map(string)
        )

    @staticmethod
    def stubbed_agent_addresses() -> strategies.SearchStrategy[
        tuple[str, type[OSError], str]
    ]:
        """Generate agent addresses for the stubbed agents.

        These are all error calls.  Non-error calls are supplied by the
        explicit examples.

        """
        invalid_url = (
            str(pathlib.Path("~").expanduser()),
            FileNotFoundError,
            os.strerror(errno.ENOENT),
        )
        protocol_not_supported = (
            "stub-ssh-agent:EPROTONOSUPPORT",
            OSError,
            os.strerror(errno.EPROTONOSUPPORT),
        )
        invalid_error_code = (
            "stub-ssh-agent:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            OSError,
            os.strerror(errno.EINVAL),
        )
        return strategies.sampled_from([
            invalid_url,
            protocol_not_supported,
            invalid_error_code,
        ])


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

    # TODO(the-13th-letter): Put RSA key mangling into helper method.
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


class TestStubbedSSHAgentSocket:
    """Test the stubbed SSH agent socket: common machinery."""

    @contextlib.contextmanager
    def _get_agent(
        self, *, extended_agent: bool | None = False
    ) -> Generator[machinery.StubbedSSHAgentSocket, None, None]:
        agent_class: type[machinery.StubbedSSHAgentSocket] = (
            machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA
            if extended_agent
            else machinery.StubbedSSHAgentSocketWithAddress
            if extended_agent is not None
            else machinery.StubbedSSHAgentSocket
        )
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            if issubclass(
                agent_class, machinery.StubbedSSHAgentSocketWithAddress
            ):
                monkeypatch.setenv("SSH_AUTH_SOCK", agent_class.ADDRESS)
            else:
                monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
            yield stack.enter_context(agent_class())


class TestStubbedSSHAgentSocketRequests(TestStubbedSSHAgentSocket):
    """Test the stubbed SSH agent socket: normal requests."""

    @Parametrize.QUERY_EXTENSION
    def test_query_extensions(
        self, extended_agent: bool, query_response: bytes
    ) -> None:
        """The agent implements a known list of extensions.

        The list is empty for the base agent, and non-empty for the
        extended agent.

        """
        query_request = (
            # SSH string header
            b"\x00\x00\x00\x0a"
            # request code: SSH_AGENTC_EXTENSION
            b"\x1b"
            # payload: SSH string "query"
            b"\x00\x00\x00\x05query"
        )
        with self._get_agent(extended_agent=extended_agent) as agent:
            assert ("query" in agent.enabled_extensions) == bool(
                extended_agent
            )
            agent.sendall(query_request)
            assert agent.recv(1000) == query_response

    @Parametrize.LIST_IDENTITIES
    def test_request_identities(
        self, extended_agent: bool | None, query_request: bytes
    ) -> None:
        """The agent implements a known list of identities.

        The extended agent implements PuTTY's `list-extended` extension.

        """
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        with self._get_agent(extended_agent=extended_agent) as agent:
            agent.sendall(query_request)
            message_length = int.from_bytes(agent.recv(4), "big")
            orig_message: bytes | bytearray = bytearray(
                agent.recv(message_length)
            )
            assert (
                orig_message[0] == _types.SSH_AGENT.SUCCESS
                if extended_agent
                else _types.SSH_AGENT.IDENTITIES_ANSWER
            )
            identity_count = int.from_bytes(orig_message[1:5], "big")
            message = bytes(orig_message[5:])
            for _ in range(identity_count):
                key, message = unstring_prefix(message)
                _comment, message = unstring_prefix(message)
                flags, message = (
                    unstring_prefix(message)
                    if extended_agent
                    else (b"", message)
                )
                assert not extended_agent or flags == b"\x00\x00\x00\x00"
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
        requires_deterministic_dsa: bool,
    ) -> None:
        """The agent signs known key/message pairs."""
        del ssh_test_key_type
        signature_types = (
            [
                data.SSHTestKeyDeterministicSignatureClass.RFC_6979,
                data.SSHTestKeyDeterministicSignatureClass.Pageant_068_080,
            ]
            if requires_deterministic_dsa
            else [data.SSHTestKeyDeterministicSignatureClass.SPEC]
        )
        signature_names = [t.name for t in signature_types]
        expected_signatures = {
            ssh_test_key.expected_signatures[t].signature
            for t in signature_types
            if ssh_test_key.expected_signatures[t].signature is not None
        }
        assert expected_signatures, (
            f"expected a known {'/'.join(signature_names)} deterministic signature"
        )
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
        query_responses = {
            string(
                # response code: SSH_AGENT_SIGN_RESPONSE
                b"\x0e"
                # expected payload: the binary signature as recorded in the test key data structure
                + string(sig)
            )
            for sig in expected_signatures
        }
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv(
                "SSH_AUTH_SOCK",
                machinery.StubbedSSHAgentSocketWithAddress.ADDRESS,
            )
            agent: machinery.StubbedSSHAgentSocket = (
                machinery.StubbedSSHAgentSocketWithAddressAndDeterministicDSA()
                if requires_deterministic_dsa
                else machinery.StubbedSSHAgentSocket()
            )
            with agent:
                agent.sendall(query_request)
                assert agent.recv(1000) in query_responses


class TestStubbedSSHAgentSocketProperOperations(TestStubbedSSHAgentSocket):
    """Test the stubbed SSH agent socket: proper use and misuse."""

    def test_close_multiple(
        self,
    ) -> None:
        """The agent can be closed repeatedly."""
        with self._get_agent(extended_agent=None) as agent:
            pass
        with agent:
            pass
        del agent

    def test_closed_agents_cannot_be_interacted_with(
        self,
    ) -> None:
        """The agent cannot be usefully used after close."""
        with self._get_agent(extended_agent=None) as agent:
            pass
        query_request = (
            # SSH string header
            b"\x00\x00\x00\x0a"
            # request code: SSH_AGENTC_EXTENSION
            b"\x1b"
            # payload: SSH string "query"
            b"\x00\x00\x00\x05query"
        )
        with pytest.raises(OSError, match=re.escape(os.strerror(errno.EBADF))):
            agent.sendall(query_request)
        with pytest.raises(OSError, match=re.escape(os.strerror(errno.EBADF))):
            agent.recv(100)

    def test_no_recv_without_sendall(
        self,
    ) -> None:
        """The agent requires a message before sending a response."""
        with self._get_agent(extended_agent=None) as agent:  # noqa: SIM117
            with pytest.raises(
                AssertionError,
                match=re.escape(
                    machinery.StubbedSSHAgentSocket._PROTOCOL_VIOLATION
                ),
            ):
                agent.recv(100)

    @hypothesis.given(
        query_request_parts=Strategies.proper_bytestring_partition(
            b"\x00\x00\x00\x0a\x1b\x00\x00\x00\x05query"
        )
    )
    @hypothesis.example(
        query_request_parts=[
            b"",
            b"\x00\x00\x00",
            b"\x0a",
            b"\x1b",
            b"\x00\x00\x00\x05",
            b"query",
        ]
    )
    def test_piecemeal_sendall(
        self,
        query_request_parts: list[bytes],
    ) -> None:
        """The agent supports receiving messages incrementally."""
        with self._get_agent(extended_agent=None) as agent:
            agent.enabled_extensions = frozenset({"query"})
            for part in query_request_parts:
                agent.sendall(part)
            header = agent.recv(agent.HEADER_SIZE)
            count = int.from_bytes(header, "big", signed=False)
            payload = agent.recv(count)
            assert len(payload) == count
            assert bytes.startswith(
                payload,
                (
                    bytes(_types.SSH_AGENT.SUCCESS),
                    bytes(_types.SSH_AGENT.EXTENSION_RESPONSE),
                ),
            )
            code = payload[: agent.CODE_SIZE]
            assert code == bytes(_types.SSH_AGENT.SUCCESS) or code == bytes(
                _types.SSH_AGENT.EXTENSION_RESPONSE
            )

    @hypothesis.given(message=Strategies.invalid_ssh_agent_messages())
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

    @hypothesis.given(message=Strategies.truncated_agent_request())
    @hypothesis.example(message=b"\x00\x00\x00\x0f\xff")
    def test_truncated_ssh_agent_message(
        self,
        message: bytes,
    ) -> None:
        """The agent diagnoses a final truncated request message."""
        with pytest.raises(  # noqa: SIM117
            AssertionError,
            match=re.escape(
                machinery.StubbedSSHAgentSocket._INCOMPLETE_REQUEST
            ),
        ):
            with self._get_agent(extended_agent=None) as agent:
                agent.sendall(message)


class TestStubbedSSHAgentSocketSupportedAndUnsupportedFeatures(
    TestStubbedSSHAgentSocket
):
    """Test the stubbed SSH agent socket: supported/unsupported features."""

    @hypothesis.given(message=Strategies.unsupported_ssh_agent_messages())
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
        with self._get_agent(extended_agent=None) as agent:
            agent.sendall(message)
            assert agent.recv(100) == query_response

    @hypothesis.given(args_tuple=Strategies.stubbed_agent_addresses())
    @hypothesis.example(args_tuple=(None, KeyError, "SSH_AUTH_SOCK"))
    @hypothesis.example(args_tuple=("stub-ssh-agent:", None, ""))
    def test_addresses(
        self,
        args_tuple: tuple[str | None, type[Exception] | None, str],
    ) -> None:
        """The agent accepts addresses."""
        address, exception, match = args_tuple
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
