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


class Test001ExporterUtils:
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
    def test200_get_vault_key(
        self,
        monkeypatch: pytest.MonkeyPatch,
        expected: str,
        vault_key: str | None,
        logname: str | None,
        user: str | None,
        username: str | None,
    ) -> None:
        priority_list = [
            ('VAULT_KEY', vault_key),
            ('LOGNAME', logname),
            ('USER', user),
            ('USERNAME', username),
        ]
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch, runner=runner
        ):
            for key, value in priority_list:
                if value is not None:
                    monkeypatch.setenv(key, value)
            assert os.fsdecode(exporter.get_vault_key()) == expected

    @pytest.mark.parametrize(
        ['expected', 'path'],
        [
            ('/tmp', '/tmp'),
            ('~', os.path.curdir),
            ('~/.vault', None),
        ],
    )
    def test_210_get_vault_path(
        self,
        monkeypatch: pytest.MonkeyPatch,
        expected: str,
        path: str | None,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch, runner=runner
        ):
            if path:
                monkeypatch.setenv('VAULT_PATH', path)
            assert os.fsdecode(
                os.path.realpath(exporter.get_vault_path())
            ) == os.path.realpath(os.path.expanduser(expected))

    def test_300_get_vault_key_without_envs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv('VAULT_KEY', raising=False)
        monkeypatch.delenv('LOGNAME', raising=False)
        monkeypatch.delenv('USER', raising=False)
        monkeypatch.delenv('USERNAME', raising=False)
        with pytest.raises(KeyError, match='VAULT_KEY'):
            exporter.get_vault_key()

    def test_310_get_vault_path_without_home(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(os.path, 'expanduser', lambda x: x)
        with pytest.raises(
            RuntimeError, match='[Cc]annot determine home directory'
        ):
            exporter.get_vault_path()


class Test002CLI:
    def test_300_invalid_format(
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
                ['-f', 'INVALID', 'VAULT_PATH'],
                catch_exceptions=False,
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert b'Invalid value for' in result.stderr_bytes
        assert b'-f' in result.stderr_bytes
        assert b'--format' in result.stderr_bytes
        assert b'INVALID' in result.stderr_bytes
