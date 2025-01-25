# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import os
import pathlib
from typing import TYPE_CHECKING, Any

import click.testing
import pytest

import tests
from derivepassphrase import cli, exporter

if TYPE_CHECKING:
    from typing_extensions import Buffer


class Test001ExporterUtils:
    """Test the utility functions in the `exporter` subpackage."""

    @pytest.mark.parametrize(
        ['expected', 'vault_key', 'logname', 'user', 'username'],
        [
            ('4username', None, None, None, '4username'),
            ('3user', None, None, '3user', None),
            ('3user', None, None, '3user', '4username'),
            ('2logname', None, '2logname', None, None),
            ('2logname', None, '2logname', None, '4username'),
            ('2logname', None, '2logname', '3user', None),
            ('2logname', None, '2logname', '3user', '4username'),
            ('1vault_key', '1vault_key', None, None, None),
            ('1vault_key', '1vault_key', None, None, '4username'),
            ('1vault_key', '1vault_key', None, '3user', None),
            ('1vault_key', '1vault_key', None, '3user', '4username'),
            ('1vault_key', '1vault_key', '2logname', None, None),
            ('1vault_key', '1vault_key', '2logname', None, '4username'),
            ('1vault_key', '1vault_key', '2logname', '3user', None),
            ('1vault_key', '1vault_key', '2logname', '3user', '4username'),
        ],
    )
    def test_200_get_vault_key(
        self,
        expected: str,
        vault_key: str | None,
        logname: str | None,
        user: str | None,
        username: str | None,
    ) -> None:
        """Look up the vault key in `VAULT_KEY`/`LOGNAME`/`USER`/`USERNAME`.

        The correct environment variable value is used, according to
        their relative priorities.

        """
        priority_list = [
            ('VAULT_KEY', vault_key),
            ('LOGNAME', logname),
            ('USER', user),
            ('USERNAME', username),
        ]
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch, runner=runner
                )
            )
            for key, value in priority_list:
                if value is not None:
                    monkeypatch.setenv(key, value)
            assert os.fsdecode(exporter.get_vault_key()) == expected

    @pytest.mark.parametrize(
        ['expected', 'path'],
        [
            (pathlib.Path('/tmp'), pathlib.Path('/tmp')),
            (pathlib.Path('~'), pathlib.Path()),
            (pathlib.Path('~/.vault'), None),
        ],
    )
    def test_210_get_vault_path(
        self,
        expected: pathlib.Path,
        path: str | os.PathLike[str] | None,
    ) -> None:
        """Determine the vault path from `VAULT_PATH`.

        Handle relative paths, absolute paths, and missing paths.

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_exporter_config(
                    monkeypatch=monkeypatch, runner=runner
                )
            )
            if path:
                monkeypatch.setenv(
                    'VAULT_PATH', os.fspath(path) if path is not None else None
                )
            assert (
                exporter.get_vault_path().resolve()
                == expected.expanduser().resolve()
            )

    def test_220_register_export_vault_config_data_handler(self) -> None:
        """Register vault config data export handlers."""

        def handler(  # pragma: no cover
            path: str | bytes | os.PathLike | None = None,
            key: str | Buffer | None = None,
            *,
            format: str,
        ) -> Any:
            del path, key
            raise ValueError(format)

        with pytest.MonkeyPatch.context() as monkeypatch:
            registry = {'dummy': handler}
            monkeypatch.setattr(
                exporter, '_export_vault_config_data_registry', registry
            )
            dec = exporter.register_export_vault_config_data_handler(
                'name1',
                'name2',
            )
            assert dec(handler) == handler
            assert registry == {
                'dummy': handler,
                'name1': handler,
                'name2': handler,
            }

    def test_300_get_vault_key_without_envs(self) -> None:
        """Fail to look up the vault key in the empty environment."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.delenv('VAULT_KEY', raising=False)
            monkeypatch.delenv('LOGNAME', raising=False)
            monkeypatch.delenv('USER', raising=False)
            monkeypatch.delenv('USERNAME', raising=False)
            with pytest.raises(KeyError, match='VAULT_KEY'):
                exporter.get_vault_key()

    def test_310_get_vault_path_without_home(self) -> None:
        """Fail to look up the vault path without `HOME`."""

        def raiser(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError('Cannot determine home directory.')  # noqa: EM101,TRY003

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(pathlib.Path, 'expanduser', raiser)
            monkeypatch.setattr(os.path, 'expanduser', raiser)
            with pytest.raises(
                RuntimeError, match=r'[Cc]annot determine home directory'
            ):
                exporter.get_vault_path()

    @pytest.mark.parametrize(
        ['namelist', 'err_pat'],
        [
            pytest.param((), '[Nn]o names given', id='empty'),
            pytest.param(
                ('name1', '', 'name2'),
                '[Uu]nder an empty name',
                id='empty-string',
            ),
            pytest.param(
                ('dummy', 'name1', 'name2'),
                '[Aa]lready registered',
                id='existing',
            ),
        ],
    )
    def test_320_register_export_vault_config_data_handler_errors(
        self,
        namelist: tuple[str, ...],
        err_pat: str,
    ) -> None:
        """Fail to register a vault config data export handler.

        Fail because e.g. the associated name is missing, or already
        present in the handler registry.

        """

        def handler(  # pragma: no cover
            path: str | bytes | os.PathLike | None = None,
            key: str | Buffer | None = None,
            *,
            format: str,
        ) -> Any:
            del path, key
            raise ValueError(format)

        with pytest.MonkeyPatch.context() as monkeypatch:
            registry = {'dummy': handler}
            monkeypatch.setattr(
                exporter, '_export_vault_config_data_registry', registry
            )
            with pytest.raises(ValueError, match=err_pat):
                exporter.register_export_vault_config_data_handler(*namelist)(
                    handler
                )

    def test_321_export_vault_config_data_bad_handler(self) -> None:
        """Fail to export vault config data without known handlers."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                exporter, '_export_vault_config_data_registry', {}
            )
            monkeypatch.setattr(
                exporter, 'find_vault_config_data_handlers', lambda: None
            )
            with pytest.raises(
                ValueError,
                match=r'Invalid vault native configuration format',
            ):
                exporter.export_vault_config_data(format='v0.3')


class Test002CLI:
    """Test the command-line functionality of the `exporter` subpackage."""

    def test_300_invalid_format(self) -> None:
        """Reject invalid vault configuration format names."""
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
                ['-f', 'INVALID', 'VAULT_PATH'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        for snippet in ('Invalid value for', '-f', '--format', 'INVALID'):
            assert result.error_exit(error=snippet), (
                'expected error exit and known error message'
            )

    @tests.skip_if_cryptography_support
    @pytest.mark.parametrize(
        ['format', 'config', 'key'],
        [
            pytest.param(
                'v0.2',
                tests.VAULT_V02_CONFIG,
                tests.VAULT_MASTER_KEY,
                id='v0.2',
            ),
            pytest.param(
                'v0.3',
                tests.VAULT_V03_CONFIG,
                tests.VAULT_MASTER_KEY,
                id='v0.3',
            ),
            pytest.param(
                'storeroom',
                tests.VAULT_STOREROOM_CONFIG_ZIPPED,
                tests.VAULT_MASTER_KEY,
                id='storeroom',
            ),
        ],
    )
    def test_999_no_cryptography_error_message(
        self,
        caplog: pytest.LogCaptureFixture,
        format: str,
        config: str | bytes,
        key: str,
    ) -> None:
        """Abort export call if no cryptography is available."""
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
                    vault_key=key,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_export_vault,
                ['-f', format, 'VAULT_PATH'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error=tests.CANNOT_LOAD_CRYPTOGRAPHY,
            record_tuples=caplog.record_tuples,
        ), 'expected error exit and known error message'
