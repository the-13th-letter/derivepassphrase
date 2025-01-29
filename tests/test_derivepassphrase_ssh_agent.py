# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Test OpenSSH key loading and signing."""

from __future__ import annotations

import base64
import contextlib
import io
import re
import socket
from typing import TYPE_CHECKING

import click
import click.testing
import hypothesis
import pytest
from hypothesis import strategies

import tests
from derivepassphrase import _types, cli, ssh_agent, vault

if TYPE_CHECKING:
    from collections.abc import Iterable

    from typing_extensions import Any, Buffer


class TestStaticFunctionality:
    """Test the static functionality of the `ssh_agent` module."""

    @staticmethod
    def as_ssh_string(bytestring: bytes) -> bytes:
        """Return an encoded SSH string from a bytestring.

        This is a helper function for hypothesis data generation.

        """
        return int.to_bytes(len(bytestring), 4, 'big') + bytestring

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
    @pytest.mark.parametrize(
        ['public_key', 'public_key_data'],
        [
            (val.public_key, val.public_key_data)
            for val in tests.SUPPORTED_KEYS.values()
        ],
        ids=list(tests.SUPPORTED_KEYS.keys()),
    )
    def test_100_key_decoding(
        self, public_key: bytes, public_key_data: bytes
    ) -> None:
        """The [`tests.ALL_KEYS`][] public key data looks sane."""
        keydata = base64.b64decode(public_key.split(None, 2)[1])
        assert keydata == public_key_data, (
            "recorded public key data doesn't match"
        )

    @pytest.mark.parametrize(
        ['line', 'env_name', 'value'],
        [
            pytest.param(
                'SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK;',
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
                id='value-export-semicolon-pageant',
            ),
            pytest.param(
                'SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270; export SSH_AUTH_SOCK;',
                'SSH_AUTH_SOCK',
                '/tmp/ssh-3CSTC1W5M22A/agent.27270',
                id='value-export-semicolon-openssh',
            ),
            pytest.param(
                'SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK',
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
                id='value-export-pageant',
            ),
            pytest.param(
                'export SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270;',
                'SSH_AUTH_SOCK',
                '/tmp/ssh-3CSTC1W5M22A/agent.27270',
                id='export-value-semicolon-openssh',
            ),
            pytest.param(
                'export SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170',
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
                id='export-value-pageant',
            ),
            pytest.param(
                'SSH_AGENT_PID=27170; export SSH_AGENT_PID;',
                'SSH_AGENT_PID',
                '27170',
                id='pid-export-semicolon',
            ),
            pytest.param(
                'SSH_AGENT_PID=27170; export SSH_AGENT_PID',
                'SSH_AGENT_PID',
                '27170',
                id='pid-export',
            ),
            pytest.param(
                'export SSH_AGENT_PID=27170;',
                'SSH_AGENT_PID',
                '27170',
                id='export-pid-semicolon',
            ),
            pytest.param(
                'export SSH_AGENT_PID=27170',
                'SSH_AGENT_PID',
                '27170',
                id='export-pid',
            ),
            pytest.param(
                'export VARIABLE=value; export OTHER_VARIABLE=other_value;',
                'VARIABLE',
                None,
                id='export-too-much',
            ),
            pytest.param(
                'VARIABLE=value',
                'VARIABLE',
                None,
                id='no-export',
            ),
        ],
    )
    def test_190_sh_export_line_parsing(
        self, line: str, env_name: str, value: str | None
    ) -> None:
        """[`tests.parse_sh_export_line`][] works."""
        if value is not None:
            assert tests.parse_sh_export_line(line, env_name=env_name) == value
        else:
            with pytest.raises(ValueError, match='Cannot parse sh line:'):
                tests.parse_sh_export_line(line, env_name=env_name)

    def test_200_constructor_no_running_agent(
        self,
        skip_if_no_af_unix_support: None,
    ) -> None:
        """Abort if the running agent cannot be located."""
        del skip_if_no_af_unix_support
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
            with pytest.raises(
                KeyError, match='SSH_AUTH_SOCK environment variable'
            ):
                ssh_agent.SSHAgentClient()

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            pytest.param(16777216, b'\x01\x00\x00\x00', id='16777216'),
        ],
    )
    def test_210_uint32(self, input: int, expected: bytes | bytearray) -> None:
        """`uint32` encoding works."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert uint32(input) == expected

    @hypothesis.given(strategies.integers(min_value=0, max_value=0xFFFFFFFF))
    @hypothesis.example(0xDEADBEEF).via('manual, pre-hypothesis example')
    def test_210a_uint32_from_number(self, num: int) -> None:
        """`uint32` encoding works, starting from numbers."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert int.from_bytes(uint32(num), 'big', signed=False) == num

    @hypothesis.given(strategies.binary(min_size=4, max_size=4))
    @hypothesis.example(b'\xde\xad\xbe\xef').via(
        'manual, pre-hypothesis example'
    )
    def test_210b_uint32_from_bytestring(self, bytestring: bytes) -> None:
        """`uint32` encoding works, starting from length four byte strings."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert (
            uint32(int.from_bytes(bytestring, 'big', signed=False))
            == bytestring
        )

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            pytest.param(
                b'ssh-rsa',
                b'\x00\x00\x00\x07ssh-rsa',
                id='ssh-rsa',
            ),
            pytest.param(
                b'ssh-ed25519',
                b'\x00\x00\x00\x0bssh-ed25519',
                id='ssh-ed25519',
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(b'ssh-ed25519'),
                b'\x00\x00\x00\x0f\x00\x00\x00\x0bssh-ed25519',
                id='string(ssh-ed25519)',
            ),
        ],
    )
    def test_211_string(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        """SSH string encoding works."""
        string = ssh_agent.SSHAgentClient.string
        assert bytes(string(input)) == expected

    @hypothesis.given(strategies.binary(max_size=0x0001FFFF))
    @hypothesis.example(b'DEADBEEF' * 10000).via(
        'manual, pre-hypothesis example with highest order bit set'
    )
    def test_211a_string_from_bytestring(self, bytestring: bytes) -> None:
        """SSH string encoding works, starting from a byte string."""
        res = ssh_agent.SSHAgentClient.string(bytestring)
        assert res.startswith((b'\x00\x00', b'\x00\x01'))
        assert int.from_bytes(res[:4], 'big', signed=False) == len(bytestring)
        assert res[4:] == bytestring

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            pytest.param(
                b'\x00\x00\x00\x07ssh-rsa',
                b'ssh-rsa',
                id='ssh-rsa',
            ),
            pytest.param(
                ssh_agent.SSHAgentClient.string(b'ssh-ed25519'),
                b'ssh-ed25519',
                id='ssh-ed25519',
            ),
        ],
    )
    def test_212_unstring(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        """SSH string decoding works."""
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        assert bytes(unstring(input)) == expected
        assert tuple(bytes(x) for x in unstring_prefix(input)) == (
            expected,
            b'',
        )

    @hypothesis.given(strategies.binary(max_size=0x00FFFFFF))
    @hypothesis.example(b'\x00\x00\x00\x07ssh-rsa').via(
        'manual, pre-hypothesis example to attempt to detect double-decoding'
    )
    @hypothesis.example(b'\x00\x00\x00\x01').via(
        'detect no-op encoding via ill-formed SSH string'
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
        assert unstring_prefix(encoded) == (bytestring, b'')
        trailing_data = b'  trailing data'
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

    @pytest.mark.parametrize(
        ['value', 'exc_type', 'exc_pattern'],
        [
            pytest.param(
                10000000000000000,
                OverflowError,
                'int too big to convert',
                id='10000000000000000',
            ),
            pytest.param(
                -1,
                OverflowError,
                "can't convert negative int to unsigned",
                id='-1',
            ),
        ],
    )
    def test_310_uint32_exceptions(
        self, value: int, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """`uint32` encoding fails for out-of-bound values."""
        uint32 = ssh_agent.SSHAgentClient.uint32
        with pytest.raises(exc_type, match=exc_pattern):
            uint32(value)

    @pytest.mark.parametrize(
        ['input', 'exc_type', 'exc_pattern'],
        [
            pytest.param(
                'some string', TypeError, 'invalid payload type', id='str'
            ),
        ],
    )
    def test_311_string_exceptions(
        self, input: Any, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        """SSH string encoding fails for non-strings."""
        string = ssh_agent.SSHAgentClient.string
        with pytest.raises(exc_type, match=exc_pattern):
            string(input)

    @pytest.mark.parametrize(
        ['input', 'exc_type', 'exc_pattern', 'has_trailer', 'parts'],
        [
            pytest.param(
                b'ssh',
                ValueError,
                'malformed SSH byte string',
                False,
                None,
                id='unencoded',
            ),
            pytest.param(
                b'\x00\x00\x00\x08ssh-rsa',
                ValueError,
                'malformed SSH byte string',
                False,
                None,
                id='truncated',
            ),
            pytest.param(
                b'\x00\x00\x00\x04XXX trailing text',
                ValueError,
                'malformed SSH byte string',
                True,
                (b'XXX ', b'trailing text'),
                id='trailing-data',
            ),
        ],
    )
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


class TestAgentInteraction:
    """Test actually talking to the SSH agent."""

    # TODO(the-13th-letter): Convert skip into xfail, and include the
    # key type in the skip/xfail message.  This means the key type needs
    # to be passed to the test function as well.
    @pytest.mark.parametrize(
        'ssh_test_key',
        list(tests.SUPPORTED_KEYS.values()),
        ids=tests.SUPPORTED_KEYS.keys(),
    )
    def test_200_sign_data_via_agent(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        ssh_test_key: tests.SSHTestKey,
    ) -> None:
        """Signing data with specific SSH keys works.

        Single tests may abort early (skip) if the indicated key is not
        loaded in the agent.  Presumably this means the key type is
        unsupported.

        """
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = ssh_test_key.public_key_data
        expected_signature = ssh_test_key.expected_signature
        derived_passphrase = ssh_test_key.derived_passphrase
        assert expected_signature is not None
        assert derived_passphrase is not None
        if public_key_data not in key_comment_pairs:  # pragma: no cover
            pytest.skip('prerequisite SSH key not loaded')
        signature = bytes(
            client.sign(payload=vault.Vault.UUID, key=public_key_data)
        )
        assert signature == expected_signature, 'SSH signature mismatch'
        signature2 = bytes(
            client.sign(payload=vault.Vault.UUID, key=public_key_data)
        )
        assert signature2 == expected_signature, 'SSH signature mismatch'
        assert (
            vault.Vault.phrase_from_key(public_key_data, conn=client)
            == derived_passphrase
        ), 'SSH signature mismatch'

    # TODO(the-13th-letter): Include the key type in the skip message.
    # This means the key type needs to be passed to the test function as
    # well.
    @pytest.mark.parametrize(
        'ssh_test_key',
        list(tests.UNSUITABLE_KEYS.values()),
        ids=tests.UNSUITABLE_KEYS.keys(),
    )
    def test_201_sign_data_via_agent_unsupported(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        ssh_test_key: tests.SSHTestKey,
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
            pytest.skip('prerequisite SSH key not loaded')
        assert not vault.Vault.is_suitable_ssh_key(
            public_key_data, client=None
        ), 'Expected key to be unsuitable in general'
        if vault.Vault.is_suitable_ssh_key(public_key_data, client=client):
            pytest.skip('agent automatically ensures key is suitable')
        with pytest.raises(ValueError, match='unsuitable SSH key'):
            vault.Vault.phrase_from_key(public_key_data, conn=client)

    @pytest.mark.parametrize(
        ['key', 'single'],
        [
            (value.public_key_data, False)
            for value in tests.SUPPORTED_KEYS.values()
        ]
        + [(tests.list_keys_singleton()[0].key, True)],
        ids=[*tests.SUPPORTED_KEYS.keys(), 'singleton'],
    )
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
            always = {v.public_key_data for v in tests.SUPPORTED_KEYS.values()}
            dsa = {
                v.public_key_data
                for k, v in tests.UNSUITABLE_KEYS.items()
                if k.startswith(('dsa', 'ecdsa'))
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
                'list_keys',
                tests.list_keys_singleton,
            )
            keys = [
                pair.key
                for pair in tests.list_keys_singleton()
                if key_is_suitable(pair.key)
            ]
            index = '1'
            text = 'Use this key? yes\n'
        else:
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            keys = [
                pair.key
                for pair in tests.list_keys()
                if key_is_suitable(pair.key)
            ]
            index = str(1 + keys.index(key))
            n = len(keys)
            text = f'Your selection? (1-{n}, leave empty to abort): {index}\n'
        b64_key = base64.standard_b64encode(key).decode('ASCII')

        @click.command()
        def driver() -> None:
            """Call `cli._select_ssh_key` directly, as a command."""
            key = cli._select_ssh_key()
            click.echo(base64.standard_b64encode(key).decode('ASCII'))

        # TODO(the-13th-letter): (Continued from above.)  Update input
        # data to use `index`/`input` directly and unconditionally.
        runner = click.testing.CliRunner(mix_stderr=True)
        result_ = runner.invoke(
            driver,
            [],
            input=('yes\n' if single else f'{index}\n'),
            catch_exceptions=True,
        )
        result = tests.ReadableResult.parse(result_)
        for snippet in ('Suitable SSH keys:\n', text, f'\n{b64_key}\n'):
            assert result.clean_exit(output=snippet), 'expected clean exit'

    def test_300_constructor_bad_running_agent(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """Fail if the agent address is invalid."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket + '~')
            sock = socket.socket(family=socket.AF_UNIX)
            with pytest.raises(OSError):  # noqa: PT011
                ssh_agent.SSHAgentClient(socket=sock)

    def test_301_constructor_no_af_unix_support(self) -> None:
        """Fail without [`socket.AF_UNIX`][] support."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv('SSH_AUTH_SOCK', "the value doesn't matter")
            monkeypatch.delattr(socket, 'AF_UNIX', raising=False)
            with pytest.raises(
                NotImplementedError,
                match='UNIX domain sockets',
            ):
                ssh_agent.SSHAgentClient()

    @pytest.mark.parametrize(
        'response',
        [
            b'\x00\x00',
            b'\x00\x00\x00\x1f some bytes missing',
        ],
        ids=['in-header', 'in-body'],
    )
    def test_310_truncated_server_response(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
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
            monkeypatch.setattr(client, '_connection', pseudo_socket)
            with pytest.raises(EOFError):
                client.request(255, b'')

    @pytest.mark.parametrize(
        ['response_code', 'response', 'exc_type', 'exc_pattern'],
        [
            pytest.param(
                _types.SSH_AGENT.FAILURE,
                b'',
                ssh_agent.SSHAgentFailedError,
                'failed to complete the request',
                id='failed-to-complete',
            ),
            pytest.param(
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b'\x00\x00\x00\x01',
                EOFError,
                'truncated response',
                id='truncated-response',
            ),
            pytest.param(
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b'\x00\x00\x00\x00abc',
                ssh_agent.TrailingDataError,
                'Overlong response',
                id='overlong-response',
            ),
        ],
    )
    def test_320_list_keys_error_responses(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
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
            monkeypatch.setattr(client, 'request', request)
            with pytest.raises(exc_type, match=exc_pattern):
                client.list_keys()

    @pytest.mark.parametrize(
        [
            'key',
            'check',
            'response_code',
            'response',
            'exc_type',
            'exc_pattern',
        ],
        [
            pytest.param(
                b'invalid-key',
                True,
                _types.SSH_AGENT.FAILURE,
                b'',
                KeyError,
                'target SSH key not loaded into agent',
                id='key-not-loaded',
            ),
            pytest.param(
                tests.SUPPORTED_KEYS['ed25519'].public_key_data,
                True,
                _types.SSH_AGENT.FAILURE,
                b'',
                ssh_agent.SSHAgentFailedError,
                'failed to complete the request',
                id='failed-to-complete',
            ),
        ],
    )
    def test_330_sign_error_responses(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
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
            monkeypatch.setattr(client, 'request', request)
            Pair = _types.SSHKeyCommentPair  # noqa: N806
            com = b'no comment'
            loaded_keys = [
                Pair(v.public_key_data, com).toreadonly()
                for v in tests.SUPPORTED_KEYS.values()
            ]
            monkeypatch.setattr(client, 'list_keys', lambda: loaded_keys)
            with pytest.raises(exc_type, match=exc_pattern):
                client.sign(key, b'abc', check_if_key_loaded=check)

    @pytest.mark.parametrize(
        ['request_code', 'response_code', 'exc_type', 'exc_pattern'],
        [
            pytest.param(
                _types.SSH_AGENTC.REQUEST_IDENTITIES,
                _types.SSH_AGENT.SUCCESS,
                ssh_agent.SSHAgentFailedError,
                re.escape(
                    f'[Code {_types.SSH_AGENT.IDENTITIES_ANSWER.value}]'
                ),
                id='REQUEST_IDENTITIES-expect-SUCCESS',
            ),
        ],
    )
    def test_340_request_error_responses(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
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
            client.request(request_code, b'', response_code=response_code)

    @pytest.mark.parametrize(
        'response_data',
        [
            pytest.param(b'\xde\xad\xbe\xef', id='truncated'),
            pytest.param(
                b'\x00\x00\x00\x0fwrong extension', id='wrong-extension'
            ),
            pytest.param(
                b'\x00\x00\x00\x05query\xde\xad\xbe\xef', id='with-trailer'
            ),
            pytest.param(
                b'\x00\x00\x00\x05query\x00\x00\x00\x04ext1\x00\x00',
                id='with-extra-fields',
            ),
        ],
    )
    def test_350_query_extensions_malformed_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        response_data: bytes,
    ) -> None:
        """Fail on malformed responses while querying extensions."""
        del running_ssh_agent

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
            assert payload == b'\x00\x00\x00\x05query'
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
            monkeypatch2.setattr(client, 'request', request)
            with pytest.raises(
                RuntimeError,
                match=r'Malformed response|does not match request',
            ):
                client.query_extensions()
