# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import json
import pathlib
import types
from typing import TYPE_CHECKING

import hypothesis
import pytest
from hypothesis import strategies

from derivepassphrase import _types, cli, exporter
from derivepassphrase.exporter import storeroom, vault_native
from tests import data, machinery
from tests.machinery import pytest as pytest_machinery

cryptography = pytest.importorskip("cryptography", minversion="38.0")

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
    from collections.abc import Callable, Iterator
    from typing import Any

    from typing_extensions import Buffer, Literal


class Parametrize(types.SimpleNamespace):
    BAD_CONFIG = pytest.mark.parametrize(
        "config", ["xxx", "null", '{"version": 255}']
    )
    VAULT_NATIVE_CONFIG_DATA = pytest.mark.parametrize(
        ["config", "format", "config_data"],
        [
            pytest.param(
                data.VAULT_V02_CONFIG,
                "v0.2",
                data.VAULT_V02_CONFIG_DATA,
                id="V02_CONFIG-v0.2",
            ),
            pytest.param(
                data.VAULT_V02_CONFIG,
                "v0.3",
                exporter.NotAVaultConfigError,
                id="V02_CONFIG-v0.3",
            ),
            pytest.param(
                data.VAULT_V03_CONFIG,
                "v0.2",
                exporter.NotAVaultConfigError,
                id="V03_CONFIG-v0.2",
            ),
            pytest.param(
                data.VAULT_V03_CONFIG,
                "v0.3",
                data.VAULT_V03_CONFIG_DATA,
                id="V03_CONFIG-v0.3",
            ),
        ],
    )
    VAULT_NATIVE_PARSER_CLASS_DATA = pytest.mark.parametrize(
        ["config", "parser_class", "config_data"],
        [
            pytest.param(
                data.VAULT_V02_CONFIG,
                vault_native.VaultNativeV02ConfigParser,
                data.VAULT_V02_CONFIG_DATA,
                id="0.2",
            ),
            pytest.param(
                data.VAULT_V03_CONFIG,
                vault_native.VaultNativeV03ConfigParser,
                data.VAULT_V03_CONFIG_DATA,
                id="0.3",
            ),
        ],
    )
    STOREROOM_HANDLER = pytest.mark.parametrize(
        "handler",
        [
            pytest.param(storeroom.export_storeroom_data, id="handler"),
            pytest.param(exporter.export_vault_config_data, id="dispatcher"),
        ],
    )
    VAULT_NATIVE_HANDLER = pytest.mark.parametrize(
        "handler",
        [
            pytest.param(vault_native.export_vault_native_data, id="handler"),
            pytest.param(exporter.export_vault_config_data, id="dispatcher"),
        ],
    )
    VAULT_NATIVE_PBKDF2_RESULT = pytest.mark.parametrize(
        ["iterations", "result"],
        [
            pytest.param(100, b"6ede361e81e9c061efcdd68aeb768b80", id="100"),
            pytest.param(200, b"bcc7d01e075b9ffb69e702bf701187c1", id="200"),
        ],
    )
    KEY_FORMATS = pytest.mark.parametrize(
        "key",
        [
            None,
            pytest.param(data.VAULT_MASTER_KEY, id="str"),
            pytest.param(data.VAULT_MASTER_KEY.encode("ascii"), id="bytes"),
            pytest.param(
                bytearray(data.VAULT_MASTER_KEY.encode("ascii")),
                id="bytearray",
            ),
            pytest.param(
                memoryview(data.VAULT_MASTER_KEY.encode("ascii")),
                id="memoryview",
            ),
        ],
    )
    BAD_MASTER_KEYS_DATA = pytest.mark.parametrize(
        ["master_keys_data", "err_msg"],
        [
            pytest.param(
                '{"version": 255}',
                "bad or unsupported keys version header",
                id="v255",
            ),
            pytest.param(
                '{"version": 1}\nAAAA\nAAAA',
                "trailing data; cannot make sense",
                id="trailing-data",
            ),
            pytest.param(
                '{"version": 1}\nAAAA',
                "cannot handle version 0 encrypted keys",
                id="v0-keys",
            ),
        ],
    )
    PATH = pytest.mark.parametrize("path", [".vault", None])
    BAD_STOREROOM_CONFIG_DATA = pytest.mark.parametrize(
        ["zipped_config", "error_text"],
        [
            pytest.param(
                data.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED,
                "Object key mismatch",
                id="VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED",
            ),
            pytest.param(
                data.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2,
                "Directory index is not actually an index",
                id="VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED2",
            ),
            pytest.param(
                data.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3,
                "Directory index is not actually an index",
                id="VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED3",
            ),
            pytest.param(
                data.VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4,
                "Object key mismatch",
                id="VAULT_STOREROOM_BROKEN_DIR_CONFIG_ZIPPED4",
            ),
        ],
    )


class TestCLIParameters:
    """Test the command-line interface for `derivepassphrase export vault`."""

    def _test(
        self,
        command_line: list[str],
        *,
        vault_config: str | bytes = data.VAULT_V03_CONFIG,
        config_data: dict[str, Any] = data.VAULT_V03_CONFIG_DATA,
    ) -> None:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                    vault_key=data.VAULT_MASTER_KEY,
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_export_vault,
                command_line,
            )
        assert result.clean_exit(empty_stderr=True), "expected clean exit"
        assert json.loads(result.stdout) == config_data

    def test_path(self) -> None:
        """The path `VAULT_PATH` is supported.

        Using `VAULT_PATH` as the path looks up the actual path in the
        `VAULT_PATH` environment variable.  See
        [`exporter.get_vault_path`][] for details.

        """
        self._test(["VAULT_PATH"])

    def test_key(self) -> None:
        """The `--key` option is supported."""
        self._test(["-k", data.VAULT_MASTER_KEY, ".vault"])

    @pytest_machinery.Parametrize.VAULT_CONFIG_FORMATS_DATA
    def test_load_vault_specific_format(
        self,
        config: str | bytes,
        format: str,
        config_data: dict[str, Any],
    ) -> None:
        """Passing a specific format works.

        Passing a specific format name causes `derivepassphrase export
        vault` to only attempt decoding in that named format.

        """
        self._test(
            ["-f", format, "-k", data.VAULT_MASTER_KEY, "VAULT_PATH"],
            vault_config=config,
            config_data=config_data,
        )


class TestCLIFailures:
    """Test the command-line interface for `derivepassphrase export vault`."""

    @contextlib.contextmanager
    def _test(
        self,
        caplog: pytest.LogCaptureFixture,
        command_line: list[str],
        /,
        error_message: str = "Cannot parse '.vault' "
        "as a valid vault-native config",
        *,
        vault_config: str | bytes = data.VAULT_V03_CONFIG,
        vault_key: str = data.VAULT_MASTER_KEY,
    ) -> Iterator[pytest.MonkeyPatch]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                    vault_key=vault_key,
                )
            )
            yield monkeypatch
            result = runner.invoke(
                cli.derivepassphrase_export_vault,
                command_line,
            )
        assert result.error_exit(
            error=error_message,
            record_tuples=caplog.record_tuples,
        ), "expected error exit and known error message"
        assert data.CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr

    def test_file_not_found(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail when trying to decode non-existant files/directories."""
        with self._test(
            caplog,
            ["does-not-exist.txt"],
            error_message="Cannot parse 'does-not-exist.txt' "
            "as a valid vault-native config",
        ):
            pass

    def test_invalid_encrypted_contents(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse invalid vault configurations (files)."""
        with self._test(caplog, [".vault"], vault_config=""):
            pass

    def test_just_a_directory(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse invalid vault configurations (directories)."""
        with self._test(caplog, [".vault"], vault_config=""):
            p = pathlib.Path(".vault")
            p.unlink()
            p.mkdir()

    def test_bad_signature(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse vault configurations with invalid integrity checks."""
        with self._test(
            caplog,
            ["-f", "v0.3", ".vault"],
            vault_config=data.VAULT_V02_CONFIG,
        ):
            pass

    def test_invalid_decrypted_contents(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Fail to parse encrypted vault configurations with invalid plaintext."""
        with self._test(
            caplog, [".vault"], error_message="Invalid vault config: "
        ) as monkeypatch:

            def export_vault_config_data(*_args: Any, **_kwargs: Any) -> None:
                return None

            monkeypatch.setattr(
                exporter,
                "export_vault_config_data",
                export_vault_config_data,
            )


class TestStoreroom:
    """Test the "storeroom" handler and handler machinery."""

    @contextlib.contextmanager
    def _setup_environment(
        self,
        *,
        vault_config: str | bytes = data.VAULT_STOREROOM_CONFIG_ZIPPED,
        vault_key: str = data.VAULT_MASTER_KEY,
    ) -> Iterator[tuple[pytest.MonkeyPatch, machinery.CliRunner]]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                    vault_key=vault_key,
                )
            )
            yield monkeypatch, runner

    @Parametrize.PATH
    @Parametrize.KEY_FORMATS
    @Parametrize.STOREROOM_HANDLER
    def test_export_data_path_and_keys_type(
        self,
        path: str | None,
        key: str | Buffer | None,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Support different argument types.

        The [`exporter.export_vault_config_data`][] dispatcher supports
        them as well.

        """
        with self._setup_environment():
            assert (
                handler(path, key, format="storeroom")
                == data.VAULT_STOREROOM_CONFIG_DATA
            )

    def test_decrypt_bucket_item_unknown_version(self) -> None:
        """Fail on unknown versions of the master keys file."""
        bucket_item = (
            b"\xff" + bytes(storeroom.ENCRYPTED_KEYPAIR_SIZE) + bytes(3)
        )
        master_keys = _types.StoreroomMasterKeys(
            encryption_key=bytes(storeroom.KEY_SIZE),
            signing_key=bytes(storeroom.KEY_SIZE),
            hashing_key=bytes(storeroom.KEY_SIZE),
        )
        with pytest.raises(ValueError, match="Cannot handle version 255"):
            storeroom._decrypt_bucket_item(bucket_item, master_keys)

    @Parametrize.BAD_CONFIG
    def test_decrypt_bucket_file_bad_json_or_version(
        self,
        config: str,
    ) -> None:
        """Fail on bad or unsupported bucket file contents.

        These include unknown versions, invalid JSON, or JSON of the
        wrong shape.

        """
        master_keys = _types.StoreroomMasterKeys(
            encryption_key=bytes(storeroom.KEY_SIZE),
            signing_key=bytes(storeroom.KEY_SIZE),
            hashing_key=bytes(storeroom.KEY_SIZE),
        )
        with self._setup_environment():
            p = pathlib.Path(".vault", "20")
            with p.open("w", encoding="UTF-8") as outfile:
                print(config, file=outfile)
            with pytest.raises(ValueError, match="Invalid bucket file: "):
                list(storeroom._decrypt_bucket_file(p, master_keys))

    @Parametrize.BAD_MASTER_KEYS_DATA
    @Parametrize.STOREROOM_HANDLER
    def test_export_storeroom_data_bad_master_keys_file(
        self,
        master_keys_data: str,
        err_msg: str,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """Fail on bad or unsupported master keys file contents.

        These include unknown versions, and data of the wrong shape.

        """
        with self._setup_environment():
            p = pathlib.Path(".vault", ".keys")
            with p.open("w", encoding="UTF-8") as outfile:
                print(master_keys_data, file=outfile)
            with pytest.raises(RuntimeError, match=err_msg):
                handler(format="storeroom")

    @Parametrize.BAD_STOREROOM_CONFIG_DATA
    @Parametrize.STOREROOM_HANDLER
    def test_export_storeroom_data_bad_directory_listing(
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
        with self._setup_environment(vault_config=zipped_config):  # noqa: SIM117
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with pytest.raises(RuntimeError, match=error_text):
                handler(format="storeroom")

    def test_decrypt_keys_wrong_data_length(self) -> None:
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
        key = b"DEADBEEFdeadbeefDeAdBeEfdEaDbEeF"
        padder = padding.PKCS7(storeroom.IV_SIZE * 8).padder()
        plaintext = bytearray(padder.update(payload))
        plaintext.extend(padder.finalize())
        iv = b"deadbeefDEADBEEF"
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
            match=r"Invalid encrypted master keys payload",
        ):
            storeroom._decrypt_master_keys_data(
                data,
                _types.StoreroomKeyPair(encryption_key=key, signing_key=key),
            )
        with pytest.raises(
            ValueError,
            match=r"Invalid encrypted session keys payload",
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
    def test_decrypt_keys_invalid_signature(self, data: bytes) -> None:
        """Fail on bad MAC values."""
        key = b"DEADBEEFdeadbeefDeAdBeEfdEaDbEeF"
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

    @contextlib.contextmanager
    def _setup_environment(
        self,
        *,
        vault_config: str | bytes = data.VAULT_V03_CONFIG,
        vault_key: str = data.VAULT_MASTER_KEY,
    ) -> Iterator[tuple[pytest.MonkeyPatch, machinery.CliRunner]]:
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                    vault_key=vault_key,
                )
            )
            yield monkeypatch, runner

    @Parametrize.VAULT_NATIVE_PBKDF2_RESULT
    def test_pbkdf2_manually(self, iterations: int, result: bytes) -> None:
        """The PBKDF2 helper function works."""
        assert (
            vault_native.VaultNativeConfigParser._pbkdf2(
                data.VAULT_MASTER_KEY.encode("utf-8"), 32, iterations
            )
            == result
        )

    @Parametrize.VAULT_NATIVE_CONFIG_DATA
    @Parametrize.VAULT_NATIVE_HANDLER
    def test_export_vault_native_data_explicit_version(
        self,
        config: str,
        format: Literal["v0.2", "v0.3"],
        config_data: _types.VaultConfig | type[Exception],
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
        with self._setup_environment(vault_config=config):
            if isinstance(config_data, type):
                with pytest.raises(config_data):
                    handler(None, format=format)
            else:
                parsed_config = handler(None, format=format)
                assert parsed_config == config_data

    @Parametrize.PATH
    @Parametrize.KEY_FORMATS
    @Parametrize.VAULT_NATIVE_HANDLER
    def test_export_data_path_and_keys_type(
        self,
        path: str | None,
        key: str | Buffer | None,
        handler: exporter.ExportVaultConfigDataFunction,
    ) -> None:
        """The handler supports different argument types.

        The [`exporter.export_vault_config_data`][] dispatcher supports
        them as well.

        """
        with self._setup_environment():
            assert (
                handler(path, key, format="v0.3") == data.VAULT_V03_CONFIG_DATA
            )

    @Parametrize.VAULT_NATIVE_PARSER_CLASS_DATA
    def test_result_caching(
        self,
        config: str,
        parser_class: type[vault_native.VaultNativeConfigParser],
        config_data: dict[str, Any],
    ) -> None:
        """Cache the results of decrypting/decoding a configuration."""

        def null_func(name: str) -> Callable[..., None]:
            def func(*_args: Any, **_kwargs: Any) -> None:  # pragma: no cover
                msg = f"disallowed and stubbed out function {name} called"
                raise AssertionError(msg)

            return func

        with self._setup_environment(vault_config=config) as values:
            monkeypatch, _ = values
            parser = parser_class(
                base64.b64decode(config), data.VAULT_MASTER_KEY
            )
            assert parser() == config_data
            # Now stub out all functions used to calculate the above result.
            monkeypatch.setattr(
                parser, "_parse_contents", null_func("_parse_contents")
            )
            monkeypatch.setattr(
                parser, "_derive_keys", null_func("_derive_keys")
            )
            monkeypatch.setattr(
                parser, "_check_signature", null_func("_check_signature")
            )
            monkeypatch.setattr(
                parser, "_decrypt_payload", null_func("_decrypt_payload")
            )
            assert parser() == config_data
            super_call = vault_native.VaultNativeConfigParser.__call__
            assert super_call(parser) == config_data

    def test_no_password(self) -> None:
        """Fail on empty master keys/master passphrases."""
        with pytest.raises(ValueError, match="Password must not be empty"):
            vault_native.VaultNativeV03ConfigParser(b"", b"")
