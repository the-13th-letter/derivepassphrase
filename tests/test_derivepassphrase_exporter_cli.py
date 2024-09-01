# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import click.testing
import pytest

import tests
from derivepassphrase.exporter import cli, storeroom, vault_native

cryptography = pytest.importorskip('cryptography', minversion='38.0')

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['VAULT_PATH'],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == tests.VAULT_V03_CONFIG_DATA

    def test_201_key_parameter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
        ):
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['-k', tests.VAULT_MASTER_KEY, '.vault'],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == tests.VAULT_V03_CONFIG_DATA

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['-f', format, '-k', tests.VAULT_MASTER_KEY, 'VAULT_PATH'],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == config_data

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['does-not-exist.txt'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert (
            b"Cannot parse 'does-not-exist.txt' as a valid config"
            in result.stderr_bytes
        )
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['.vault'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert (
            b"Cannot parse '.vault' as a valid config." in result.stderr_bytes
        )
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['-f', 'v0.3', '.vault'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert (
            b"Cannot parse '.vault' as a valid config." in result.stderr_bytes
        )
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes

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
            result = runner.invoke(
                cli.derivepassphrase_export,
                ['.vault'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert b'Invalid vault config: ' in result.stderr_bytes
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes


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

    def test_403_export_storeroom_data_bad_directory_listing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with (
            tests.isolated_vault_exporter_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=tests.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED,
                vault_key=tests.VAULT_MASTER_KEY,
            ),
            pytest.raises(RuntimeError, match='Object key mismatch'),
        ):
            storeroom.export_storeroom_data()


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
