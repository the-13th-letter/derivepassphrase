#!/usr/bin/python3
# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Get signatures/derived passphrases for test keys from a "real" SSH agent.

Attempt to upload every known test key against the running SSH agent and
generate signatures and the derived passphrase from it.  If this is
successful, then print the test key in a (quasi) `repr` format for
inclusion in the tests module source code.

This script is intended for use to capture "known good" values for the
test keys: what the current SSH agent thinks are the correct signature
and derived passphrase for the respective key (if supported).  It works
especially well with OpenSSH's `ssh-agent` and PuTTY's `pageant` on UNIX
systems:

    $ ssh-agent python3 test_key_signatures_and_outputs.py
    ...
    $ pageant --exec python3 test_key_signatures_and_outputs.py
    ...

"""

from __future__ import annotations

import argparse
import textwrap

import tests

from derivepassphrase import _types, ssh_agent, vault  # noqa: PLC2701


def try_key(
    client: ssh_agent.SSHAgentClient,
    keyname: str,
    /,
    *,
    deterministic_signature_class: (
        tests.SSHTestKeyDeterministicSignatureClass
    ) = tests.SSHTestKeyDeterministicSignatureClass.RFC_6979,
) -> tests.SSHTestKey | None:
    """Query a signature and derived passphrase for the named key, if possible.

    Args:
        client:
            A connected SSH agent client.
        keyname:
            The name of the test key, from [`tests.ALL_KEYS`][].
        deterministic_signature_class:
            The class of deterministic signatures to record this
            signature as, if the key turns out to be agent-specifically
            suitable, but not suitable in general.  Usually, this will
            be either
            [RFC 6979][tests.SSHTestKeyDeterministicSignatureClass.RFC_6979]
            or
            [Pageant 0.68–0.80][tests.SSHTestKeyDeterministicSignatureClass.PAGEANT_068_080],
            for deterministic DSA signatures.  (Use
            [`SPEC`][tests.SSHTestKeyDeterministicSignatureClass.SPEC]
            to disable.)

    Returns:
        A modified SSH test key, augmented with the new signature, or
        `None` if no such signature augmentation could be performed.

    """  # noqa: E501,RUF002
    key = tests.ALL_KEYS[keyname]
    if not vault.Vault.is_suitable_ssh_key(key.public_key_data, client=client):
        return None
    signature: bytes
    derived_passphrase: bytes
    try:
        client.request(_types.SSH_AGENTC.ADD_IDENTITY, key.private_key_blob)
    except ssh_agent.SSHAgentFailedError:
        return None
    try:
        signature = client.sign(key.public_key_data, vault.Vault.UUID)
        derived_passphrase = vault.Vault.phrase_from_key(key.public_key_data)
    except ssh_agent.SSHAgentFailedError:
        return None
    expected_signatures = dict(key.expected_signatures)
    signature_class = (
        tests.SSHTestKeyDeterministicSignatureClass.SPEC
        if vault.Vault.is_suitable_ssh_key(key.public_key_data)
        else deterministic_signature_class
    )
    expected_signatures[signature_class] = (
        tests.SSHTestKeyDeterministicSignature(
            signature=signature,
            derived_passphrase=derived_passphrase,
            signature_class=signature_class,
        )
    )
    return tests.SSHTestKey(
        public_key=key.public_key,
        public_key_data=key.public_key_data,
        private_key=key.private_key,
        private_key_blob=key.private_key_blob,
        expected_signatures=expected_signatures,
    )


def format_key(key: tests.SSHTestKey) -> str:
    """Return a formatted SSH test key."""
    ascii_printables = range(32, 127)
    ascii_whitespace = {ord(' '), ord('\n'), ord('\t'), ord('\r'), ord('\f')}

    def as_raw_string_or_hex(bytestring: bytes) -> str:
        if bytestring.find(b'"""') < 0 and all(
            byte in ascii_printables or byte in ascii_whitespace
            for byte in bytestring
        ):
            return f'rb"""{bytestring.decode("ascii")}"""'
        hexstring = bytestring.hex(' ', 1)
        wrapped_hexstring = '\n'.join(
            textwrap.TextWrapper(width=48).wrap(hexstring)
        )
        return f'''bytes.fromhex("""
{wrapped_hexstring}
""")'''

    f = as_raw_string_or_hex

    lines = [
        'SSHTestKey(\n',
        '    public_key=' + f(key.public_key) + ',\n',
        '    public_key_data=' + f(key.public_key_data) + ',\n',
        '    private_key=' + f(key.private_key) + ',\n',
        '    private_key_blob=' + f(key.private_key_blob) + ',\n',
    ]
    if key.expected_signatures:
        expected_signature_lines = [
            'expected_signatures={\n',
        ]
        for sig in key.expected_signatures.values():
            expected_signature_lines.extend([
                f'    {sig.signature_class!s}: '
                'SSHTestKeyDeterministicSignature(\n',
                '        signature=' + f(sig.signature) + ',\n',
                '        derived_passphrase='
                + f(sig.derived_passphrase)
                + ',\n',
            ])
            if (
                sig.signature_class
                != tests.SSHTestKeyDeterministicSignatureClass.SPEC
            ):
                expected_signature_lines.append(
                    f'        signature_class={sig.signature_class!s},\n'
                )
            expected_signature_lines.append('    ),\n')
        expected_signature_lines.append('},\n')
        lines.extend('    ' + x for x in expected_signature_lines)
    else:
        lines.append('    expected_signatures={},\n')
    lines.append(')')

    return ''.join(lines)


def main(argv: list[str] | None = None) -> None:
    """"""  # noqa: D419
    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group()
    group.add_argument(
        '--rfc-6979',
        action='store_const',
        dest='deterministic_signature_class',
        const=tests.SSHTestKeyDeterministicSignatureClass.RFC_6979,
        default=tests.SSHTestKeyDeterministicSignatureClass.RFC_6979,
        help='assume RFC 6979 signatures for deterministic DSA',
    )
    group.add_argument(
        '--pageant-068-080',
        action='store_const',
        dest='deterministic_signature_class',
        const=tests.SSHTestKeyDeterministicSignatureClass.Pageant_068_080,
        default=tests.SSHTestKeyDeterministicSignatureClass.RFC_6979,
        help='assume Pageant 0.68-0.80 signatures for deterministic DSA',
    )
    ap.add_argument(
        'keynames',
        nargs='*',
        metavar='KEYNAME',
        help='query the named test key in the agent '
        '(multiple use possible; default: all keys)',
    )
    args = ap.parse_args(args=argv)
    if not args.keynames:
        args.keynames = list(tests.ALL_KEYS.keys())
    with ssh_agent.SSHAgentClient.ensure_agent_subcontext() as client:
        for keyname in args.keynames:
            key = try_key(
                client,
                keyname,
                deterministic_signature_class=args.deterministic_signature_class,
            )
            if key is not None:
                print(f'keys[{keyname!r}] =', format_key(key))


if __name__ == '__main__':
    main()
