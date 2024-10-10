# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import strategies

import tests
from derivepassphrase import cli
from derivepassphrase.exporter import storeroom, vault_native

cryptography = pytest.importorskip('cryptography', minversion='38.0')

from cryptography.hazmat.primitives import (  # noqa: E402
    ciphers,
    hashes,
    hmac,
    padding,
)
from cryptography.hazmat.primitives.ciphers import (  # noqa: E402
    algorithms,
    modes,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any


class TestCLI:
    def test_200_path_parameter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            monkeypatch.setenv('VAULT_KEY', tests.VAULT_MASTER_KEY)
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert json.loads(result.output) == tests.VAULT_V03_CONFIG_DATA

    def test_201_key_parameter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-k', tests.VAULT_MASTER_KEY, '.vault'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert json.loads(result.output) == tests.VAULT_V03_CONFIG_DATA

    @pytest.mark.parametrize(
        ['format', 'config', 'config_data'],
        [
            pytest.param(
                'v0.2',
                tests.VAULT_V02_CONFIG,
                tests.VAULT_V02_CONFIG_DATA,
                id='0.2',
            ),
            pytest.param(
                'v0.3',
                tests.VAULT_V03_CONFIG,
                tests.VAULT_V03_CONFIG_DATA,
                id='0.3',
            ),
            pytest.param(
                'storeroom',
                tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                tests.VAULT_STOREROOM_CONFIG_DATA,
                id='storeroom',
            ),
        ],
    )
    def test_210_load_vault_v02_v03_storeroom(
        self,
        monkeypatch: pytest.MonkeyPatch,
        format: str,
        config: str | bytes,
        config_data: dict[str, Any],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=config,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-f', format, '-k', tests.VAULT_MASTER_KEY, 'VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert json.loads(result.output) == config_data

    # test_300_invalid_format is found in
    # tests.test_derivepassphrase_export::Test002CLI

    def test_301_vault_config_not_found(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['does-not-exist.txt'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error="Cannot parse 'does-not-exist.txt' as a valid config"
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_302_vault_config_invalid(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config='',
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['.vault'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error="Cannot parse '.vault' as a valid config"
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_403_invalid_vault_config_bad_signature(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V02_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-f', 'v0.3', '.vault'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error="Cannot parse '.vault' as a valid config"
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_500_vault_config_invalid_internal(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):

            def _load_data(*_args: Any, **_kwargs: Any) -> None:
                return None

            monkeypatch.setattr(cli, '_load_data', _load_data)
            _result = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['.vault'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Invalid vault config: '
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr


class TestStoreroom:
    @pytest.mark.parametrize(
        ['path', 'key'],
        [
            ('.vault', tests.VAULT_MASTER_KEY),
            ('.vault', None),
            (None, tests.VAULT_MASTER_KEY),
            (None, None),
        ],
    )
    def test_200_export_data_path_and_keys_type(
        self,
        monkeypatch: pytest.MonkeyPatch,
        path: str | None,
        key: str | None,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            assert (
                storeroom.export_storeroom_data(path, key)
                == tests.VAULT_STOREROOM_CONFIG_DATA
            )

    def test_400_decrypt_bucket_item_unknown_version(self) -> None:
        bucket_item = (
            b'\xff' + bytes(storeroom.ENCRYPTED_KEYPAIR_SIZE) + bytes(3)
        )
        master_keys: storeroom.MasterKeys = {
            'encryption_key': bytes(storeroom.KEY_SIZE),
            'signing_key': bytes(storeroom.KEY_SIZE),
            'hashing_key': bytes(storeroom.KEY_SIZE),
        }
        with pytest.raises(ValueError, match='Cannot handle version 255'):
            storeroom.decrypt_bucket_item(bucket_item, master_keys)

    @pytest.mark.parametrize('config', ['xxx', 'null', '{"version": 255}'])
    def test_401_decrypt_bucket_file_bad_json_or_version(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        master_keys: storeroom.MasterKeys = {
            'encryption_key': bytes(storeroom.KEY_SIZE),
            'signing_key': bytes(storeroom.KEY_SIZE),
            'hashing_key': bytes(storeroom.KEY_SIZE),
        }
        with (
            tests.isolated_vault_exporter_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
            ),
        ):
            with open('.vault/20', 'w', encoding='UTF-8') as outfile:
                print(config, file=outfile)
            with pytest.raises(ValueError, match='Invalid bucket file: '):
                list(storeroom.decrypt_bucket_file('.vault/20', master_keys))

    @pytest.mark.parametrize(
        ['data', 'err_msg'],
        [
            ('{"version": 255}', 'bad or unsupported keys version header'),
            ('{"version": 1}\nAAAA\nAAAA', 'trailing data; cannot make sense'),
            ('{"version": 1}\nAAAA', 'cannot handle version 0 encrypted keys'),
        ],
    )
    def test_402_export_storeroom_data_bad_master_keys_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        data: str,
        err_msg: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with (
            tests.isolated_vault_exporter_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                vault_key=tests.VAULT_MASTER_KEY,
            ),
        ):
            with open('.vault/.keys', 'w', encoding='UTF-8') as outfile:
                print(data, file=outfile)
            with pytest.raises(RuntimeError, match=err_msg):
                storeroom.export_storeroom_data()

    @pytest.mark.parametrize(
        ['zipped_config', 'error_text'],
        [
            pytest.param(
                tests.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED,
                'Object key mismatch',
                id='VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED',
            ),
            pytest.param(
                tests.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2,
                'Directory index is not actually an index',
                id='VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2',
            ),
            pytest.param(
                tests.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3,
                'Directory index is not actually an index',
                id='VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3',
            ),
            pytest.param(
                tests.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4,
                'Object key mismatch',
                id='VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4',
            ),
        ],
    )
    def test_403_export_storeroom_data_bad_directory_listing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        zipped_config: bytes,
        error_text: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with (
            tests.isolated_vault_exporter_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=zipped_config,
                vault_key=tests.VAULT_MASTER_KEY,
            ),
            pytest.raises(RuntimeError, match=error_text),
        ):
            storeroom.export_storeroom_data()

    def test_404_decrypt_keys_wrong_data_length(self) -> None:
        payload = (
            b"Any text here, as long as it isn't "
            b'exactly 64 or 96 bytes long.'
        )
        assert len(payload) not in frozenset({
            2 * storeroom.KEY_SIZE,
            3 * storeroom.KEY_SIZE,
        })
        key = b'DEADBEEFdeadbeefDeAdBeEfdEaDbEeF'
        padder = padding.PKCS7(storeroom.IV_SIZE * 8).padder()
        plaintext = bytearray(padder.update(payload))
        plaintext.extend(padder.finalize())
        iv = b'deadbeefDEADBEEF'
        assert len(iv) == storeroom.IV_SIZE
        encryptor = ciphers.Cipher(
            algorithms.AES256(key), modes.CBC(iv)
        ).encryptor()
        ciphertext = bytearray(encryptor.update(plaintext))
        ciphertext.extend(encryptor.finalize())
        mac_obj = hmac.HMAC(key, hashes.SHA256())
        mac_obj.update(iv)
        mac_obj.update(ciphertext)
        data = iv + bytes(ciphertext) + mac_obj.finalize()
        with pytest.raises(
            ValueError,
            match=r'Invalid encrypted master keys payload',
        ):
            storeroom.decrypt_master_keys_data(
                data, {'encryption_key': key, 'signing_key': key}
            )
        with pytest.raises(
            ValueError,
            match=r'Invalid encrypted session keys payload',
        ):
            storeroom.decrypt_session_keys(
                data,
                {
                    'hashing_key': key,
                    'encryption_key': key,
                    'signing_key': key,
                },
            )

    @tests.hypothesis_settings_coverage_compatible
    @hypothesis.given(
        data=strategies.binary(
            min_size=storeroom.MAC_SIZE, max_size=storeroom.MAC_SIZE
        ),
    )
    def test_405_decrypt_keys_invalid_signature(self, data: bytes) -> None:
        key = b'DEADBEEFdeadbeefDeAdBeEfdEaDbEeF'
        # Guessing a correct payload plus MAC would be a pre-image
        # attack on the underlying hash function (SHA-256), i.e. is
        # computationally infeasible, and the chance of finding one by
        # such random sampling is astronomically tiny.
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            storeroom.decrypt_master_keys_data(
                data, {'encryption_key': key, 'signing_key': key}
            )
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            storeroom.decrypt_session_keys(
                data,
                {
                    'hashing_key': key,
                    'encryption_key': key,
                    'signing_key': key,
                },
            )


class TestVaultNativeConfig:
    @pytest.mark.parametrize(
        ['iterations', 'result'],
        [
            (100, b'6ede361e81e9c061efcdd68aeb768b80'),
            (200, b'bcc7d01e075b9ffb69e702bf701187c1'),
        ],
    )
    def test_200_pbkdf2_manually(self, iterations: int, result: bytes) -> None:
        assert (
            vault_native.VaultNativeConfigParser._pbkdf2(
                tests.VAULT_MASTER_KEY.encode('utf-8'), 32, iterations
            )
            == result
        )

    def test_201_export_vault_native_data_no_arguments(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            parsed_config = vault_native.export_vault_native_data(None)
        assert parsed_config == tests.VAULT_V03_CONFIG_DATA

    @pytest.mark.parametrize(
        ['parser_class', 'config', 'result'],
        [
            pytest.param(
                vault_native.VaultNativeV02ConfigParser,
                tests.VAULT_V02_CONFIG,
                tests.VAULT_V02_CONFIG_DATA,
                id='0.2',
            ),
            pytest.param(
                vault_native.VaultNativeV03ConfigParser,
                tests.VAULT_V03_CONFIG,
                tests.VAULT_V03_CONFIG_DATA,
                id='0.3',
            ),
        ],
    )
    def test_300_result_caching(
        self,
        monkeypatch: pytest.MonkeyPatch,
        parser_class: type[vault_native.VaultNativeConfigParser],
        config: str,
        result: dict[str, Any],
    ) -> None:
        def null_func(name: str) -> Callable[..., None]:
            def func(*_args: Any, **_kwargs: Any) -> None:  # pragma: no cover
                msg = f'disallowed and stubbed out function {name} called'
                raise AssertionError(msg)

            return func

        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=config,
        ):
            parser = parser_class(
                base64.b64decode(config), tests.VAULT_MASTER_KEY
            )
            assert parser() == result
            # Now stub out all functions used to calculate the above result.
            monkeypatch.setattr(
                parser, '_parse_contents', null_func('_parse_contents')
            )
            monkeypatch.setattr(
                parser, '_derive_keys', null_func('_derive_keys')
            )
            monkeypatch.setattr(
                parser, '_check_signature', null_func('_check_signature')
            )
            monkeypatch.setattr(
                parser, '_decrypt_payload', null_func('_decrypt_payload')
            )
            assert parser() == result
            super_call = vault_native.VaultNativeConfigParser.__call__
            assert super_call(parser) == result

    def test_400_no_password(self) -> None:
        with pytest.raises(ValueError, match='Password must not be empty'):
            vault_native.VaultNativeV03ConfigParser(b'', b'')
