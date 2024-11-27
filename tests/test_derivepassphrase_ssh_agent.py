# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test OpenSSH key loading and signing."""

from __future__ import annotations

import base64
import io
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
    @pytest.mark.parametrize(
        ['public_key', 'public_key_data'],
        [
            (val['public_key'], val['public_key_data'])
            for val in tests.SUPPORTED_KEYS.values()
        ],
    )
    def test_100_key_decoding(
        self, public_key: bytes, public_key_data: bytes
    ) -> None:
        keydata = base64.b64decode(public_key.split(None, 2)[1])
        assert (
            keydata == public_key_data
        ), "recorded public key data doesn't match"

    @pytest.mark.parametrize(
        ['line', 'env_name', 'value'],
        [
            (
                'SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK;',  # noqa: E501
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
            ),
            (
                'SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270; export SSH_AUTH_SOCK;',  # noqa: E501
                'SSH_AUTH_SOCK',
                '/tmp/ssh-3CSTC1W5M22A/agent.27270',
            ),
            (
                'SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170; export SSH_AUTH_SOCK',  # noqa: E501
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
            ),
            (
                'export SSH_AUTH_SOCK=/tmp/ssh-3CSTC1W5M22A/agent.27270;',
                'SSH_AUTH_SOCK',
                '/tmp/ssh-3CSTC1W5M22A/agent.27270',
            ),
            (
                'export SSH_AUTH_SOCK=/tmp/pageant.user/pageant.27170',
                'SSH_AUTH_SOCK',
                '/tmp/pageant.user/pageant.27170',
            ),
            (
                'SSH_AGENT_PID=27170; export SSH_AGENT_PID;',
                'SSH_AGENT_PID',
                '27170',
            ),
            (
                'SSH_AGENT_PID=27170; export SSH_AGENT_PID',
                'SSH_AGENT_PID',
                '27170',
            ),
            ('export SSH_AGENT_PID=27170;', 'SSH_AGENT_PID', '27170'),
            ('export SSH_AGENT_PID=27170', 'SSH_AGENT_PID', '27170'),
            (
                'export VARIABLE=value; export OTHER_VARIABLE=other_value;',
                'VARIABLE',
                None,
            ),
            (
                'VARIABLE=value',
                'VARIABLE',
                None,
            ),
        ],
    )
    def test_190_sh_export_line_parsing(
        self, line: str, env_name: str, value: str | None
    ) -> None:
        if value is not None:
            assert tests.parse_sh_export_line(line, env_name=env_name) == value
        else:
            with pytest.raises(ValueError, match='Cannot parse sh line:'):
                tests.parse_sh_export_line(line, env_name=env_name)

    def test_200_constructor_no_running_agent(
        self,
        monkeypatch: pytest.MonkeyPatch,
        skip_if_no_af_unix_support: None,
    ) -> None:
        del skip_if_no_af_unix_support
        monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
        with pytest.raises(
            KeyError, match='SSH_AUTH_SOCK environment variable'
        ):
            ssh_agent.SSHAgentClient()

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (16777216, b'\x01\x00\x00\x00'),
        ],
    )
    def test_210_uint32(self, input: int, expected: bytes | bytearray) -> None:
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert uint32(input) == expected

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (b'ssh-rsa', b'\x00\x00\x00\x07ssh-rsa'),
            (b'ssh-ed25519', b'\x00\x00\x00\x0bssh-ed25519'),
            (
                ssh_agent.SSHAgentClient.string(b'ssh-ed25519'),
                b'\x00\x00\x00\x0f\x00\x00\x00\x0bssh-ed25519',
            ),
        ],
    )
    def test_211_string(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        string = ssh_agent.SSHAgentClient.string
        assert bytes(string(input)) == expected

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (b'\x00\x00\x00\x07ssh-rsa', b'ssh-rsa'),
            (
                ssh_agent.SSHAgentClient.string(b'ssh-ed25519'),
                b'ssh-ed25519',
            ),
        ],
    )
    def test_212_unstring(
        self, input: bytes | bytearray, expected: bytes | bytearray
    ) -> None:
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        assert bytes(unstring(input)) == expected
        assert tuple(bytes(x) for x in unstring_prefix(input)) == (
            expected,
            b'',
        )

    @pytest.mark.parametrize(
        ['value', 'exc_type', 'exc_pattern'],
        [
            (10000000000000000, OverflowError, 'int too big to convert'),
            (-1, OverflowError, "can't convert negative int to unsigned"),
        ],
    )
    def test_310_uint32_exceptions(
        self, value: int, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        uint32 = ssh_agent.SSHAgentClient.uint32
        with pytest.raises(exc_type, match=exc_pattern):
            uint32(value)

    @pytest.mark.parametrize(
        ['input', 'exc_type', 'exc_pattern'],
        [
            ('some string', TypeError, 'invalid payload type'),
        ],
    )
    def test_311_string_exceptions(
        self, input: Any, exc_type: type[Exception], exc_pattern: str
    ) -> None:
        string = ssh_agent.SSHAgentClient.string
        with pytest.raises(exc_type, match=exc_pattern):
            string(input)

    @pytest.mark.parametrize(
        ['input', 'exc_type', 'exc_pattern', 'has_trailer', 'parts'],
        [
            (b'ssh', ValueError, 'malformed SSH byte string', False, None),
            (
                b'\x00\x00\x00\x08ssh-rsa',
                ValueError,
                'malformed SSH byte string',
                False,
                None,
            ),
            (
                b'\x00\x00\x00\x04XXX trailing text',
                ValueError,
                'malformed SSH byte string',
                True,
                (b'XXX ', b'trailing text'),
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
    @pytest.mark.parametrize(
        'data_dict',
        list(tests.SUPPORTED_KEYS.values()),
        ids=tests.SUPPORTED_KEYS.keys(),
    )
    def test_200_sign_data_via_agent(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        data_dict: tests.SSHTestKey,
    ) -> None:
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = data_dict['public_key_data']
        expected_signature = data_dict['expected_signature']
        derived_passphrase = data_dict['derived_passphrase']
        if public_key_data not in key_comment_pairs:  # pragma: no cover
            pytest.skip('prerequisite SSH key not loaded')
        signature = bytes(
            client.sign(payload=vault.Vault._UUID, key=public_key_data)
        )
        assert signature == expected_signature, 'SSH signature mismatch'
        signature2 = bytes(
            client.sign(payload=vault.Vault._UUID, key=public_key_data)
        )
        assert signature2 == expected_signature, 'SSH signature mismatch'
        assert (
            vault.Vault.phrase_from_key(public_key_data, conn=client)
            == derived_passphrase
        ), 'SSH signature mismatch'

    @pytest.mark.parametrize(
        'data_dict',
        list(tests.UNSUITABLE_KEYS.values()),
        ids=tests.UNSUITABLE_KEYS.keys(),
    )
    def test_201_sign_data_via_agent_unsupported(
        self,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        data_dict: tests.SSHTestKey,
    ) -> None:
        client = ssh_agent_client_with_test_keys_loaded
        key_comment_pairs = {bytes(k): bytes(c) for k, c in client.list_keys()}
        public_key_data = data_dict['public_key_data']
        _ = data_dict['expected_signature']
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
            (value['public_key_data'], False)
            for value in tests.SUPPORTED_KEYS.values()
        ]
        + [(tests.list_keys_singleton()[0].key, True)],
    )
    def test_210_ssh_key_selector(
        self,
        monkeypatch: pytest.MonkeyPatch,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
        key: bytes,
        single: bool,
    ) -> None:
        client = ssh_agent_client_with_test_keys_loaded

        def key_is_suitable(key: bytes) -> bool:
            always = {
                v['public_key_data'] for v in tests.SUPPORTED_KEYS.values()
            }
            dsa = {
                v['public_key_data']
                for k, v in tests.UNSUITABLE_KEYS.items()
                if k.startswith(('dsa', 'ecdsa'))
            }
            return key in always or (
                client.has_deterministic_dsa_signatures() and key in dsa
            )

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
            key = cli._select_ssh_key()
            click.echo(base64.standard_b64encode(key).decode('ASCII'))

        runner = click.testing.CliRunner(mix_stderr=True)
        _result = runner.invoke(
            driver,
            [],
            input=('yes\n' if single else f'{index}\n'),
            catch_exceptions=True,
        )
        result = tests.ReadableResult.parse(_result)
        for snippet in ('Suitable SSH keys:\n', text, f'\n{b64_key}\n'):
            assert result.clean_exit(output=snippet), 'expected clean exit'

    def test_300_constructor_bad_running_agent(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        with monkeypatch.context() as monkeypatch2:
            monkeypatch2.setenv(
                'SSH_AUTH_SOCK', running_ssh_agent.socket + '~'
            )
            sock = socket.socket(family=socket.AF_UNIX)
            with pytest.raises(OSError):  # noqa: PT011
                ssh_agent.SSHAgentClient(socket=sock)

    def test_301_constructor_no_af_unix_support(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        with monkeypatch.context() as monkeypatch2:
            monkeypatch2.setenv('SSH_AUTH_SOCK', "the value doesn't matter")
            monkeypatch2.delattr(socket, 'AF_UNIX', raising=False)
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
    )
    def test_310_truncated_server_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        response: bytes,
    ) -> None:
        del running_ssh_agent
        client = ssh_agent.SSHAgentClient()
        response_stream = io.BytesIO(response)

        class PseudoSocket:
            def sendall(self, *args: Any, **kwargs: Any) -> Any:  # noqa: ARG002
                return None

            def recv(self, *args: Any, **kwargs: Any) -> Any:
                return response_stream.read(*args, **kwargs)

        pseudo_socket = PseudoSocket()
        monkeypatch.setattr(client, '_connection', pseudo_socket)
        with pytest.raises(EOFError):
            client.request(255, b'')

    @pytest.mark.parametrize(
        ['response_code', 'response', 'exc_type', 'exc_pattern'],
        [
            (
                _types.SSH_AGENT.FAILURE,
                b'',
                ssh_agent.SSHAgentFailedError,
                'failed to complete the request',
            ),
            (
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b'\x00\x00\x00\x01',
                EOFError,
                'truncated response',
            ),
            (
                _types.SSH_AGENT.IDENTITIES_ANSWER,
                b'\x00\x00\x00\x00abc',
                ssh_agent.TrailingDataError,
                'Overlong response',
            ),
        ],
    )
    def test_320_list_keys_error_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        response_code: _types.SSH_AGENT,
        response: bytes | bytearray,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
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

        with monkeypatch.context() as monkeypatch2:
            client = ssh_agent.SSHAgentClient()
            monkeypatch2.setattr(client, 'request', request)
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
            (
                b'invalid-key',
                True,
                _types.SSH_AGENT.FAILURE,
                b'',
                KeyError,
                'target SSH key not loaded into agent',
            ),
            (
                tests.SUPPORTED_KEYS['ed25519']['public_key_data'],
                True,
                _types.SSH_AGENT.FAILURE,
                b'',
                ssh_agent.SSHAgentFailedError,
                'failed to complete the request',
            ),
        ],
    )
    def test_330_sign_error_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        key: bytes | bytearray,
        check: bool,
        response_code: _types.SSH_AGENT,
        response: bytes | bytearray,
        exc_type: type[Exception],
        exc_pattern: str,
    ) -> None:
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

        with monkeypatch.context() as monkeypatch2:
            client = ssh_agent.SSHAgentClient()
            monkeypatch2.setattr(client, 'request', request)
            KeyCommentPair = _types.KeyCommentPair  # noqa: N806
            loaded_keys = [
                KeyCommentPair(v['public_key_data'], b'no comment')
                for v in tests.SUPPORTED_KEYS.values()
            ]
            monkeypatch2.setattr(client, 'list_keys', lambda: loaded_keys)
            with pytest.raises(exc_type, match=exc_pattern):
                client.sign(key, b'abc', check_if_key_loaded=check)

    @pytest.mark.parametrize(
        ['request_code', 'response_code', 'exc_type', 'exc_pattern'],
        [
            (
                _types.SSH_AGENTC.REQUEST_IDENTITIES,
                _types.SSH_AGENT.SUCCESS,
                ssh_agent.SSHAgentFailedError,
                f'[Code {_types.SSH_AGENT.IDENTITIES_ANSWER.value}]',
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
        del running_ssh_agent

        with (
            pytest.raises(exc_type, match=exc_pattern),
            ssh_agent.SSHAgentClient() as client,
        ):
            client.request(request_code, b'', response_code=response_code)

    @pytest.mark.parametrize(
        'response_data',
        [
            b'\xde\xad\xbe\xef',
            b'\x00\x00\x00\x0fwrong extension',
            b'\x00\x00\x00\x05query\xde\xad\xbe\xef',
            b'\x00\x00\x00\x05query\x00\x00\x00\x04ext1\x00\x00',
        ],
    )
    def test_350_query_extensions_malformed_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        response_data: bytes,
    ) -> None:
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

        with (
            monkeypatch.context() as monkeypatch2,
            ssh_agent.SSHAgentClient() as client,
        ):
            monkeypatch2.setattr(client, 'request', request)
            with pytest.raises(
                RuntimeError,
                match='Malformed response|does not match request'
            ):
                client.query_extensions()


class TestHypotheses:
    @hypothesis.given(strategies.integers(min_value=0, max_value=0xFFFFFFFF))
    # standard example value
    @hypothesis.example(0xDEADBEEF)
    def test_210_uint32(self, num: int) -> None:
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert int.from_bytes(uint32(num), 'big', signed=False) == num

    @hypothesis.given(strategies.binary(min_size=4, max_size=4))
    # standard example value
    @hypothesis.example(b'\xde\xad\xbe\xef')
    def test_210a_uint32(self, bytestring: bytes) -> None:
        uint32 = ssh_agent.SSHAgentClient.uint32
        assert (
            uint32(int.from_bytes(bytestring, 'big', signed=False))
            == bytestring
        )

    @hypothesis.given(strategies.binary(max_size=0x0001FFFF))
    # example: highest order bit is set
    @hypothesis.example(b'DEADBEEF' * 10000)
    def test_211_string(self, bytestring: bytes) -> None:
        res = ssh_agent.SSHAgentClient.string(bytestring)
        assert res.startswith((b'\x00\x00', b'\x00\x01'))
        assert int.from_bytes(res[:4], 'big', signed=False) == len(bytestring)
        assert res[4:] == bytestring

    @hypothesis.given(strategies.binary(max_size=0x00FFFFFF))
    # example: check for double-deserialization
    @hypothesis.example(b'\x00\x00\x00\x07ssh-rsa')
    def test_212_string_unstring(self, bytestring: bytes) -> None:
        string = ssh_agent.SSHAgentClient.string
        unstring = ssh_agent.SSHAgentClient.unstring
        unstring_prefix = ssh_agent.SSHAgentClient.unstring_prefix
        encoded = string(bytestring)
        assert unstring(encoded) == bytestring
        assert unstring_prefix(encoded) == (bytestring, b'')
        trailing_data = b'  trailing data'
        encoded2 = string(bytestring) + trailing_data
        assert unstring_prefix(encoded2) == (bytestring, trailing_data)
