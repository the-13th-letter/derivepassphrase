# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import os
from typing import Any

import click.testing
import pytest

import tests
from derivepassphrase import exporter
from derivepassphrase.exporter import cli

cryptography = pytest.importorskip('cryptography', minversion='38.0')


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
