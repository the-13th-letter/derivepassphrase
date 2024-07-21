# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

"""Test OpenSSH key loading and signing."""

from __future__ import annotations

import base64
import io
import os
import socket
import subprocess

import click
import click.testing
import pytest
from typing_extensions import Any

import derivepassphrase
import derivepassphrase.cli
import ssh_agent_client
import tests


class TestStaticFunctionality:
    @pytest.mark.parametrize(
        ['public_key', 'public_key_data'],
        [
            (val['public_key'], val['public_key_data'])
            for val in tests.SUPPORTED_KEYS.values()
        ],
    )
    def test_100_key_decoding(self, public_key, public_key_data):
        keydata = base64.b64decode(public_key.split(None, 2)[1])
        assert (
            keydata == public_key_data
        ), "recorded public key data doesn't match"

    def test_200_constructor_no_running_agent(self, monkeypatch):
        monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
        sock = socket.socket(family=socket.AF_UNIX)
        with pytest.raises(
            KeyError, match='SSH_AUTH_SOCK environment variable'
        ):
            ssh_agent_client.SSHAgentClient(socket=sock)

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (16777216, b'\x01\x00\x00\x00'),
        ],
    )
    def test_210_uint32(self, input, expected):
        uint32 = ssh_agent_client.SSHAgentClient.uint32
        assert uint32(input) == expected

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (b'ssh-rsa', b'\x00\x00\x00\x07ssh-rsa'),
            (b'ssh-ed25519', b'\x00\x00\x00\x0bssh-ed25519'),
            (
                ssh_agent_client.SSHAgentClient.string(b'ssh-ed25519'),
                b'\x00\x00\x00\x0f\x00\x00\x00\x0bssh-ed25519',
            ),
        ],
    )
    def test_211_string(self, input, expected):
        string = ssh_agent_client.SSHAgentClient.string
        assert bytes(string(input)) == expected

    @pytest.mark.parametrize(
        ['input', 'expected'],
        [
            (b'\x00\x00\x00\x07ssh-rsa', b'ssh-rsa'),
            (
                ssh_agent_client.SSHAgentClient.string(b'ssh-ed25519'),
                b'ssh-ed25519',
            ),
        ],
    )
    def test_212_unstring(self, input, expected):
        unstring = ssh_agent_client.SSHAgentClient.unstring
        unstring_prefix = ssh_agent_client.SSHAgentClient.unstring_prefix
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
    def test_310_uint32_exceptions(self, value, exc_type, exc_pattern):
        uint32 = ssh_agent_client.SSHAgentClient.uint32
        with pytest.raises(exc_type, match=exc_pattern):
            uint32(value)

    @pytest.mark.parametrize(
        ['input', 'exc_type', 'exc_pattern'],
        [
            ('some string', TypeError, 'invalid payload type'),
        ],
    )
    def test_311_string_exceptions(self, input, exc_type, exc_pattern):
        string = ssh_agent_client.SSHAgentClient.string
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
        self, input, exc_type, exc_pattern, has_trailer, parts
    ):
        unstring = ssh_agent_client.SSHAgentClient.unstring
        unstring_prefix = ssh_agent_client.SSHAgentClient.unstring_prefix
        with pytest.raises(exc_type, match=exc_pattern):
            unstring(input)
        if has_trailer:
            assert tuple(bytes(x) for x in unstring_prefix(input)) == parts
        else:
            with pytest.raises(exc_type, match=exc_pattern):
                unstring_prefix(input)


@tests.skip_if_no_agent
class TestAgentInteraction:
    @pytest.mark.parametrize(
        ['keytype', 'data_dict'], list(tests.SUPPORTED_KEYS.items())
    )
    def test_200_sign_data_via_agent(self, keytype, data_dict):
        del keytype  # Unused.
        private_key = data_dict['private_key']
        try:
            _ = subprocess.run(
                ['ssh-add', '-t', '30', '-q', '-'],
                input=private_key,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            pytest.skip(
                f'uploading test key: {e!r}, stdout={e.stdout!r}, '
                f'stderr={e.stderr!r}'
            )
        else:
            try:
                client = ssh_agent_client.SSHAgentClient()
            except OSError:  # pragma: no cover
                pytest.skip('communication error with the SSH agent')
        with client:
            key_comment_pairs = {
                bytes(k): bytes(c) for k, c in client.list_keys()
            }
            public_key_data = data_dict['public_key_data']
            expected_signature = data_dict['expected_signature']
            derived_passphrase = data_dict['derived_passphrase']
            if public_key_data not in key_comment_pairs:  # pragma: no cover
                pytest.skip('prerequisite SSH key not loaded')
            signature = bytes(
                client.sign(
                    payload=derivepassphrase.Vault._UUID, key=public_key_data
                )
            )
            assert signature == expected_signature, 'SSH signature mismatch'
            signature2 = bytes(
                client.sign(
                    payload=derivepassphrase.Vault._UUID, key=public_key_data
                )
            )
            assert signature2 == expected_signature, 'SSH signature mismatch'
            assert (
                derivepassphrase.Vault.phrase_from_key(public_key_data)
                == derived_passphrase
            ), 'SSH signature mismatch'

    @pytest.mark.parametrize(
        ['keytype', 'data_dict'], list(tests.UNSUITABLE_KEYS.items())
    )
    def test_201_sign_data_via_agent_unsupported(self, keytype, data_dict):
        del keytype  # Unused.
        private_key = data_dict['private_key']
        try:
            _ = subprocess.run(
                ['ssh-add', '-t', '30', '-q', '-'],
                input=private_key,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:  # pragma: no cover
            pytest.skip(
                f'uploading test key: {e!r}, stdout={e.stdout!r}, '
                f'stderr={e.stderr!r}'
            )
        else:
            try:
                client = ssh_agent_client.SSHAgentClient()
            except OSError:  # pragma: no cover
                pytest.skip('communication error with the SSH agent')
        with client:
            key_comment_pairs = {
                bytes(k): bytes(c) for k, c in client.list_keys()
            }
            public_key_data = data_dict['public_key_data']
            _ = data_dict['expected_signature']
            if public_key_data not in key_comment_pairs:  # pragma: no cover
                pytest.skip('prerequisite SSH key not loaded')
            signature = bytes(
                client.sign(
                    payload=derivepassphrase.Vault._UUID, key=public_key_data
                )
            )
            signature2 = bytes(
                client.sign(
                    payload=derivepassphrase.Vault._UUID, key=public_key_data
                )
            )
            assert signature != signature2, 'SSH signature repeatable?!'
            with pytest.raises(ValueError, match='unsuitable SSH key'):
                derivepassphrase.Vault.phrase_from_key(public_key_data)

    @staticmethod
    def _params():
        for value in tests.SUPPORTED_KEYS.values():
            key = value['public_key_data']
            yield (key, False)
        singleton_key = tests.list_keys_singleton()[0].key
        for value in tests.SUPPORTED_KEYS.values():
            key = value['public_key_data']
            if key == singleton_key:
                yield (key, True)

    @pytest.mark.parametrize(['key', 'single'], list(_params()))
    def test_210_ssh_key_selector(self, monkeypatch, key, single):
        def key_is_suitable(key: bytes):
            return key in {
                v['public_key_data'] for v in tests.SUPPORTED_KEYS.values()
            }

        if single:
            monkeypatch.setattr(
                ssh_agent_client.SSHAgentClient,
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
                ssh_agent_client.SSHAgentClient, 'list_keys', tests.list_keys
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
        def driver():
            key = derivepassphrase.cli._select_ssh_key()
            click.echo(base64.standard_b64encode(key).decode('ASCII'))

        runner = click.testing.CliRunner(mix_stderr=True)
        result = runner.invoke(
            driver,
            [],
            input=('yes\n' if single else f'{index}\n'),
            catch_exceptions=True,
        )
        assert result.stdout.startswith(
            'Suitable SSH keys:\n'
        ), 'missing expected output'
        assert text in result.stdout, 'missing expected output'
        assert result.stdout.endswith(
            f'\n{b64_key}\n'
        ), 'missing expected output'
        assert result.exit_code == 0, 'driver program failed?!'

    del _params

    def test_300_constructor_bad_running_agent(self, monkeypatch):
        monkeypatch.setenv('SSH_AUTH_SOCK', os.environ['SSH_AUTH_SOCK'] + '~')
        sock = socket.socket(family=socket.AF_UNIX)
        with pytest.raises(OSError):  # noqa: PT011
            ssh_agent_client.SSHAgentClient(socket=sock)

    @pytest.mark.parametrize(
        'response',
        [
            b'\x00\x00',
            b'\x00\x00\x00\x1f some bytes missing',
        ],
    )
    def test_310_truncated_server_response(self, monkeypatch, response):
        client = ssh_agent_client.SSHAgentClient()
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

    @tests.skip_if_no_agent
    @pytest.mark.parametrize(
        ['response_code', 'response', 'exc_type', 'exc_pattern'],
        [
            (255, b'', RuntimeError, 'error return from SSH agent:'),
            (12, b'\x00\x00\x00\x01', EOFError, 'truncated response'),
            (
                12,
                b'\x00\x00\x00\x00abc',
                ssh_agent_client.TrailingDataError,
                'Overlong response',
            ),
        ],
    )
    def test_320_list_keys_error_responses(
        self, monkeypatch, response_code, response, exc_type, exc_pattern
    ):
        client = ssh_agent_client.SSHAgentClient()
        monkeypatch.setattr(
            client,
            'request',
            lambda *a, **kw: (response_code, response),  # noqa: ARG005
        )
        with pytest.raises(exc_type, match=exc_pattern):
            client.list_keys()

    @tests.skip_if_no_agent
    @pytest.mark.parametrize(
        ['key', 'check', 'response', 'exc_type', 'exc_pattern'],
        [
            (
                b'invalid-key',
                True,
                (255, b''),
                KeyError,
                'target SSH key not loaded into agent',
            ),
            (
                tests.SUPPORTED_KEYS['ed25519']['public_key_data'],
                True,
                (255, b''),
                RuntimeError,
                'signing data failed:',
            ),
        ],
    )
    def test_330_sign_error_responses(
        self, monkeypatch, key, check, response, exc_type, exc_pattern
    ):
        client = ssh_agent_client.SSHAgentClient()
        monkeypatch.setattr(client, 'request', lambda a, b: response)  # noqa: ARG005
        KeyCommentPair = ssh_agent_client.types.KeyCommentPair  # noqa: N806
        loaded_keys = [
            KeyCommentPair(v['public_key_data'], b'no comment')
            for v in tests.SUPPORTED_KEYS.values()
        ]
        monkeypatch.setattr(client, 'list_keys', lambda: loaded_keys)
        with pytest.raises(exc_type, match=exc_pattern):
            client.sign(key, b'abc', check_if_key_loaded=check)
