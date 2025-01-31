# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import json
import pathlib
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import strategies

import tests
from derivepassphrase import _types, cli, exporter
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

    from typing_extensions import Buffer, Literal


class TestCLI:
    """Test the command-line interface for `derivepassphrase export vault`."""

    def test_200_path_parameter(self) -> None:
        """The path `VAULT_PATH` is supported.

        Using `VAULT_PATH` as the path looks up the actual path in the
        `VAULT_PATH` environment variable.  See
        [`exporter.get_vault_path`][] for details.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V03_CONFIG,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            monkeypatch.setenv('VAULT_KEY', tests.VAULT_MASTER_KEY)
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert json.loads(result.output) == tests.VAULT_V03_CONFIG_DATA

    def test_201_key_parameter(self) -> None:
        """The `--key` option is supported."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V03_CONFIG,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-k', tests.VAULT_MASTER_KEY, '.vault'],
            )
        result = tests.ReadableResult.parse(result_)
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
        format: str,
        config: str | bytes,
        config_data: dict[str, Any],
    ) -> None:
        """Passing a specific format works.

        Passing a specific format name causes `derivepassphrase export
        vault` to only attempt decoding in that named format.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-f', format, '-k', tests.VAULT_MASTER_KEY, 'VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert json.loads(result.output) == config_data

    # test_300_invalid_format is found in
    # tests.test_derivepassphrase_export::Test002CLI

    def test_301_vault_config_not_found(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail when trying to decode non-existant files/directories."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V03_CONFIG,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['does-not-exist.txt'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error=(
                "Cannot parse 'does-not-exist.txt' "
                'as a valid vault-native config'
            ),
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_302_vault_config_invalid(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse invalid vault configurations (files)."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config='',
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['.vault'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error="Cannot parse '.vault' as a valid vault-native config",
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_302a_vault_config_invalid_just_a_directory(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse invalid vault configurations (directories)."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config='',
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            p = pathlib.Path('.vault')
            p.unlink()
            p.mkdir()
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                [str(p)],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error="Cannot parse '.vault' as a valid vault-native config",
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_403_invalid_vault_config_bad_signature(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse vault configurations with invalid integrity checks."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V02_CONFIG,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-f', 'v0.3', '.vault'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error="Cannot parse '.vault' as a valid vault-native config",
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_500_vault_config_invalid_internal(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The decoded vault configuration data is valid."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V03_CONFIG,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )

            def export_vault_config_data(*_args: Any, **_kwargs: Any) -> None:
                return None

            monkeypatch.setattr(
                exporter,
                'export_vault_config_data',
                export_vault_config_data,
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['.vault'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='Invalid vault config: ',
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
        assert tests.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr


class TestStoreroom:
    """Test the "storeroom" handler and handler machinery."""

    @pytest.mark.parametrize('path', ['.vault', None])
    @pytest.mark.parametrize(
        'key',
        [
            None,
            pytest.param(tests.VAULT_MASTER_KEY, id='str'),
            pytest.param(tests.VAULT_MASTER_KEY.encode('ascii'), id='bytes'),
            pytest.param(
                bytearray(tests.VAULT_MASTER_KEY.encode('ascii')),
                id='bytearray',
            ),
            pytest.param(
                memoryview(tests.VAULT_MASTER_KEY.encode('ascii')),
                id='memoryview',
            ),
        ],
    )
    @pytest.mark.parametrize(
        'handler',
        [
            pytest.param(storeroom.export_storeroom_data, id='handler'),
            pytest.param(exporter.export_vault_config_data, id='dispatcher'),
        ],
    )
    def test_200_export_data_path_and_keys_type(
        self,
        path: str | None,
        key: str | Buffer | None,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Support different argument types.

        The [`exporter.export_vault_config_data`][] dispatcher supports
        them as well.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            assert (
                handler(path, key, format='storeroom')
                == tests.VAULT_STOREROOM_CONFIG_DATA
            )

    def test_400_decrypt_bucket_item_unknown_version(self) -> None:
        """Fail on unknown versions of the master keys file."""
        bucket_item = (
            b'\xff' + bytes(storeroom.ENCRYPTED_KEYPAIR_SIZE) + bytes(3)
        )
        master_keys = _types.StoreroomMasterKeys(
            encryption_key=bytes(storeroom.KEY_SIZE),
            signing_key=bytes(storeroom.KEY_SIZE),
            hashing_key=bytes(storeroom.KEY_SIZE),
        )
        with pytest.raises(ValueError, match='Cannot handle version 255'):
            storeroom._decrypt_bucket_item(bucket_item, master_keys)

    @pytest.mark.parametrize('config', ['xxx', 'null', '{"version": 255}'])
    def test_401_decrypt_bucket_file_bad_json_or_version(
        self,
        config: str,
    ) -> None:
        """Fail on bad or unsupported bucket file contents.

        These include unknown versions, invalid JSON, or JSON of the
        wrong shape.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        master_keys = _types.StoreroomMasterKeys(
            encryption_key=bytes(storeroom.KEY_SIZE),
            signing_key=bytes(storeroom.KEY_SIZE),
            hashing_key=bytes(storeroom.KEY_SIZE),
        )
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                )
            )
            p = pathlib.Path('.vault', '20')
            with p.open('w', encoding='UTF-8') as outfile:
                print(config, file=outfile)
            with pytest.raises(ValueError, match='Invalid bucket file: '):
                list(storeroom._decrypt_bucket_file(p, master_keys))

    @pytest.mark.parametrize(
        ['data', 'err_msg'],
        [
            pytest.param(
                '{"version": 255}',
                'bad or unsupported keys version header',
                id='v255',
            ),
            pytest.param(
                '{"version": 1}\nAAAA\nAAAA',
                'trailing data; cannot make sense',
                id='trailing-data',
            ),
            pytest.param(
                '{"version": 1}\nAAAA',
                'cannot handle version 0 encrypted keys',
                id='v0-keys',
            ),
        ],
    )
    @pytest.mark.parametrize(
        'handler',
        [
            pytest.param(storeroom.export_storeroom_data, id='handler'),
            pytest.param(exporter.export_vault_config_data, id='dispatcher'),
        ],
    )
    def test_402_export_storeroom_data_bad_master_keys_file(
        self,
        data: str,
        err_msg: str,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Fail on bad or unsupported master keys file contents.

        These include unknown versions, and data of the wrong shape.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            p = pathlib.Path('.vault', '.keys')
            with p.open('w', encoding='UTF-8') as outfile:
                print(data, file=outfile)
            with pytest.raises(RuntimeError, match=err_msg):
                handler(format='storeroom')

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
    @pytest.mark.parametrize(
        'handler',
        [
            pytest.param(storeroom.export_storeroom_data, id='handler'),
            pytest.param(exporter.export_vault_config_data, id='dispatcher'),
        ],
    )
    def test_403_export_storeroom_data_bad_directory_listing(
        self,
        zipped_config: bytes,
        error_text: str,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Fail on bad decoded directory structures.

        If the decoded configuration contains directories whose
        structures are inconsistent, it detects this and fails:

          - The key indicates a directory, but the contents don't.
          - The directory indicates children with invalid path names.
          - The directory indicates children that are missing from the
            configuration entirely.
          - The configuration contains nested subdirectories, but the
            higher-level directories don't indicate their
            subdirectories.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=zipped_config,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            stack.enter_context(pytest.raises(RuntimeError, match=error_text))
            handler(format='storeroom')

    def test_404_decrypt_keys_wrong_data_length(self) -> None:
        """Fail on internal structural data of the wrong size.

        Specifically, fail on internal structural data such as master
        keys or session keys that is correctly encrypted according to
        its MAC, but is of the wrong shape.  (Since the data usually are
        keys and thus are opaque, the only detectable shape violation is
        the wrong size of the data.)

        """
        payload = (
            b"Any text here, as long as it isn't exactly 64 or 96 bytes long."
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
            storeroom._decrypt_master_keys_data(
                data,
                _types.StoreroomKeyPair(encryption_key=key, signing_key=key),
            )
        with pytest.raises(
            ValueError,
            match=r'Invalid encrypted session keys payload',
        ):
            storeroom._decrypt_session_keys(
                data,
                _types.StoreroomMasterKeys(
                    hashing_key=key, encryption_key=key, signing_key=key
                ),
            )

    @hypothesis.given(
        data=strategies.binary(
            min_size=storeroom.MAC_SIZE, max_size=storeroom.MAC_SIZE
        ),
    )
    def test_405_decrypt_keys_invalid_signature(self, data: bytes) -> None:
        """Fail on bad MAC values."""
        key = b'DEADBEEFdeadbeefDeAdBeEfdEaDbEeF'
        # Guessing a correct payload plus MAC would be a pre-image
        # attack on the underlying hash function (SHA-256), i.e. is
        # computationally infeasible, and the chance of finding one by
        # such random sampling is astronomically tiny.
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            storeroom._decrypt_master_keys_data(
                data,
                _types.StoreroomKeyPair(encryption_key=key, signing_key=key),
            )
        with pytest.raises(cryptography.exceptions.InvalidSignature):
            storeroom._decrypt_session_keys(
                data,
                _types.StoreroomMasterKeys(
                    hashing_key=key, encryption_key=key, signing_key=key
                ),
            )


class TestVaultNativeConfig:
    """Test the vault-native handler and handler machinery."""

    @pytest.mark.parametrize(
        ['iterations', 'result'],
        [
            pytest.param(100, b'6ede361e81e9c061efcdd68aeb768b80', id='100'),
            pytest.param(200, b'bcc7d01e075b9ffb69e702bf701187c1', id='200'),
        ],
    )
    def test_200_pbkdf2_manually(self, iterations: int, result: bytes) -> None:
        """The PBKDF2 helper function works."""
        assert (
            vault_native.VaultNativeConfigParser._pbkdf2(
                tests.VAULT_MASTER_KEY.encode('utf-8'), 32, iterations
            )
            == result
        )

    @pytest.mark.parametrize(
        ['config', 'format', 'result'],
        [
            pytest.param(
                tests.VAULT_V02_CONFIG,
                'v0.2',
                tests.VAULT_V02_CONFIG_DATA,
                id='V02_CONFIG-v0.2',
            ),
            pytest.param(
                tests.VAULT_V02_CONFIG,
                'v0.3',
                exporter.NotAVaultConfigError,
                id='V02_CONFIG-v0.3',
            ),
            pytest.param(
                tests.VAULT_V03_CONFIG,
                'v0.2',
                exporter.NotAVaultConfigError,
                id='V03_CONFIG-v0.2',
            ),
            pytest.param(
                tests.VAULT_V03_CONFIG,
                'v0.3',
                tests.VAULT_V03_CONFIG_DATA,
                id='V03_CONFIG-v0.3',
            ),
        ],
    )
    @pytest.mark.parametrize(
        'handler',
        [
            pytest.param(vault_native.export_vault_native_data, id='handler'),
            pytest.param(exporter.export_vault_config_data, id='dispatcher'),
        ],
    )
    def test_201_export_vault_native_data_explicit_version(
        self,
        config: str,
        format: Literal['v0.2', 'v0.3'],
        result: _types.VaultConfig | type[Exception],
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Accept data only of the correct version.

        Note: Historic behavior
            `derivepassphrase` versions prior to 0.5 automatically tried
            to parse vault-native configurations as v0.3-type, then
            v0.2-type.  Since `derivepassphrase` 0.5, the command-line
            interface still tries multi-version parsing, but the API
            no longer does.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            if isinstance(result, type):
                with pytest.raises(result):
                    handler(None, format=format)
            else:
                parsed_config = handler(None, format=format)
                assert parsed_config == result

    @pytest.mark.parametrize('path', ['.vault', None])
    @pytest.mark.parametrize(
        'key',
        [
            None,
            pytest.param(tests.VAULT_MASTER_KEY, id='str'),
            pytest.param(tests.VAULT_MASTER_KEY.encode('ascii'), id='bytes'),
            pytest.param(
                bytearray(tests.VAULT_MASTER_KEY.encode('ascii')),
                id='bytearray',
            ),
            pytest.param(
                memoryview(tests.VAULT_MASTER_KEY.encode('ascii')),
                id='memoryview',
            ),
        ],
    )
    @pytest.mark.parametrize(
        'handler',
        [
            pytest.param(vault_native.export_vault_native_data, id='handler'),
            pytest.param(exporter.export_vault_config_data, id='dispatcher'),
        ],
    )
    def test_202_export_data_path_and_keys_type(
        self,
        path: str | None,
        key: str | Buffer | None,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """The handler supports different argument types.

        The [`exporter.export_vault_config_data`][] dispatcher supports
        them as well.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=tests.VAULT_V03_CONFIG,
                    vault_key=tests.VAULT_MASTER_KEY,
                )
            )
            assert (
                handler(path, key, format='v0.3')
                == tests.VAULT_V03_CONFIG_DATA
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
        parser_class: type[vault_native.VaultNativeConfigParser],
        config: str,
        result: dict[str, Any],
    ) -> None:
        """Cache the results of decrypting/decoding a configuration."""

        def null_func(name: str) -> Callable[..., None]:
            def func(*_args: Any, **_kwargs: Any) -> None:  # pragma: no cover
                msg = f'disallowed and stubbed out function {name} called'
                raise AssertionError(msg)

            return func

        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
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
        """Fail on empty master keys/master passphrases."""
        with pytest.raises(ValueError, match='Password must not be empty'):
            vault_native.VaultNativeV03ConfigParser(b'', b'')
