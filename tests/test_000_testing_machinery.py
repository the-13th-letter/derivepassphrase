# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64

import pytest

import tests
from derivepassphrase import ssh_agent

OPENSSH_MAGIC = b'openssh-key-v1\x00'
OPENSSH_HEADER = (
    OPENSSH_MAGIC  # magic
    + b'\x00\x00\x00\x04none'  # ciphername
    + b'\x00\x00\x00\x04none'  # kdfname
    + b'\x00\x00\x00\x00'  # kdfoptions
    + b'\x00\x00\x00\x01'  # number of keys
)


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
    while len(secret) % 16 != 0:
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
        b'ssh-ed25519': 2,
        b'ssh-ed448': 2,
        b'ssh-rsa': 6,
        b'ssh-dss': 5,
        b'ecdsa-sha2-nistp256': 3,
        b'ecdsa-sha2-nistp384': 3,
        b'ecdsa-sha2-nistp521': 3,
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
    while len(padding) >= 8:
        padding[-8:] = b''

    new_private_block.extend(padding)
    result.extend(string(new_private_block))
    return result


class Parametrize:
    """Common test parametrizations."""

    TEST_KEYS = pytest.mark.parametrize(
        ['keyname', 'key'], tests.ALL_KEYS.items(), ids=tests.ALL_KEYS.keys()
    )


@Parametrize.TEST_KEYS
def test_100_test_keys_public_keys_are_internally_consistent(
    keyname: str,
    key: tests.SSHTestKey,
) -> None:
    """The test key public key data structures are internally consistent."""
    del keyname
    string = ssh_agent.SSHAgentClient.string
    public_key_lines = key.public_key.splitlines(keepends=False)
    assert len(public_key_lines) == 1
    line_parts = public_key_lines[0].strip(b'\r\n').split(None, 2)
    key_type_name, public_key_b64 = line_parts[:2]
    assert base64.standard_b64encode(key.public_key_data) == public_key_b64
    assert key.public_key_data.startswith(string(key_type_name))


@Parametrize.TEST_KEYS
def test_101_test_keys_private_keys_are_consistent_with_public_keys(
    keyname: str,
    key: tests.SSHTestKey,
) -> None:
    """The test key private key data are consistent with their public parts."""
    del keyname
    string = ssh_agent.SSHAgentClient.string

    if key.public_key_data.startswith(string(b'ssh-rsa')):
        # RSA public keys are *not* prefixes of the corresponding private
        # key in OpenSSH format! RSA public keys consist of an exponent
        # e and a modulus n, which in the public key are in the order (e,
        # n), but in the order (n, e) in the OpenSSH private key.  We thus
        # need to parse and rearrange the components of the public key into
        # a new "mangled" public key that then *is* a prefix of the
        # respective private key.
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
def test_102_test_keys_private_keys_are_internally_consistent(
    keyname: str,
    key: tests.SSHTestKey,
) -> None:
    """The test key private key data structures are internally consistent."""
    del keyname
    string = ssh_agent.SSHAgentClient.string

    private_key_lines = [
        line
        for line in key.private_key.splitlines(keepends=False)
        if line and not line.startswith((b'-----BEGIN', b'-----END'))
    ]
    private_key_from_openssh = base64.standard_b64decode(
        b''.join(private_key_lines)
    )
    wrapped_public_key = string(key.public_key_data)
    assert (
        private_key_from_openssh[
            len(OPENSSH_HEADER) : len(OPENSSH_HEADER) + len(wrapped_public_key)
        ]
        == wrapped_public_key
    )

    # Offset skips the header, the wrapped public key, and the framing
    # of the private keys section.
    offset = len(OPENSSH_HEADER) + len(wrapped_public_key) + 4
    checkint = int.from_bytes(
        private_key_from_openssh[offset : offset + 4], 'big'
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
