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

VAULT_MASTER_KEY = 'vault key'
VAULT_V02_CONFIG = 'P7xeh5y4jmjpJ2pFq4KUcTVoaE9ZOEkwWmpVTURSSWQxbGt6emN4aFE4eFM3anVPbDRNTGpOLzY3eDF5aE1YTm5LNWh5Q1BwWTMwM3M5S083MWRWRFlmOXNqSFJNcStGMWFOS3c2emhiOUNNenZYTmNNMnZxaUErdlRoOGF2ZHdGT1ZLNTNLOVJQcU9jWmJrR3g5N09VcVBRZ0ZnSFNUQy9HdFVWWnFteVhRVkY3MHNBdnF2ZWFEbFBseWRGelE1c3BFTnVUckRQdWJSL29wNjFxd2Y2ZVpob3VyVzRod3FKTElTenJ1WTZacTJFOFBtK3BnVzh0QWVxcWtyWFdXOXYyenNQeFNZbWt1MDU2Vm1kVGtISWIxWTBpcWRFbyswUVJudVVhZkVlNVpGWDA4WUQ2Q2JTWW81SnlhQ2Zxa3cxNmZoQjJES0Uyd29rNXpSck5iWVBrVmEwOXFya1NpMi9saU5LL3F0M3N3MjZKekNCem9ER2svWkZ0SUJLdmlHRno0VlQzQ3pqZTBWcTM3YmRiNmJjTkhqUHZoQ0NxMW1ldW1XOFVVK3pQMEtUMkRMVGNvNHFlOG40ck5KcGhsYXg1b1VzZ1NYU1B2T3RXdEkwYzg4NWE3YWUzOWI1MDI0MThhMWZjODQ3MDA2OTJmNDQ0MDkxNGFiNmRlMGQ2YjZiNjI5NGMwN2IwMmI4MGZi'  # noqa: E501
VAULT_V02_CONFIG_DATA = {
    'global': {
        'phrase': tests.DUMMY_PASSPHRASE.decode('utf-8').rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.2 format.',
        },
        tests.DUMMY_SERVICE: tests.DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_V03_CONFIG = 'sBPBrr8BFHPxSJkV/A53zk9zwDQHFxLe6UIusCVvzFQre103pcj5xxmE11lMTA0U2QTYjkhRXKkH5WegSmYpAnzReuRsYZlWWp6N4kkubf+twZ9C3EeggPm7as2Af4TICHVbX4uXpIHeQJf9y1OtqrO+SRBrgPBzgItoxsIxebxVKgyvh1CZQOSkn7BIzt9xKhDng3ubS4hQ91fB0QCumlldTbUl8tj4Xs5JbvsSlUMxRlVzZ0OgAOrSsoWELXmsp6zXFa9K6wIuZa4wQuMLQFHiA64JO1CR3I+rviWCeMlbTOuJNx6vMB5zotKJqA2hIUpN467TQ9vI4g/QTo40m5LT2EQKbIdTvBQAzcV4lOcpr5Lqt4LHED5mKvm/4YfpuuT3I3XCdWfdG5SB7ciiB4Go+xQdddy3zZMiwm1fEwIB8XjFf2cxoJdccLQ2yxf+9diedBP04EsMHrvxKDhQ7/vHl7xF2MMFTDKl3WFd23vvcjpR1JgNAKYprG/e1p/7'  # noqa: E501
VAULT_V03_CONFIG_DATA = {
    'global': {
        'phrase': tests.DUMMY_PASSPHRASE.decode('utf-8').rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in v0.3 format.',
        },
        tests.DUMMY_SERVICE: tests.DUMMY_CONFIG_SETTINGS.copy(),
    },
}
VAULT_STOREROOM_CONFIG_ZIPPED = b"""
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
"""
VAULT_STOREROOM_CONFIG_DATA = {
    'global': {
        'phrase': tests.DUMMY_PASSPHRASE.decode('utf-8').rstrip('\n'),
    },
    'services': {
        '(meta)': {
            'notes': 'This config was originally in storeroom format.',
        },
        tests.DUMMY_SERVICE: tests.DUMMY_CONFIG_SETTINGS.copy(),
    },
}

try:
    from cryptography.hazmat.primitives import ciphers
except ModuleNotFoundError:
    CRYPTOGRAPHY_SUPPORT = False
else:
    CRYPTOGRAPHY_SUPPORT = True
    del ciphers

CANNOT_LOAD_CRYPTOGRAPHY = (
    b'Cannot load the required Python module "cryptography".'
)


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
    @pytest.mark.xfail(
        not CRYPTOGRAPHY_SUPPORT, reason='cryptography module not found'
    )
    def test_200_path_parameter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=VAULT_V03_CONFIG,
            vault_key=VAULT_MASTER_KEY,
        ):
            monkeypatch.setenv('VAULT_KEY', VAULT_MASTER_KEY)
            result = runner.invoke(
                exporter.derivepassphrase_export,
                ['VAULT_PATH'],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == VAULT_V03_CONFIG_DATA

    @pytest.mark.xfail(
        not CRYPTOGRAPHY_SUPPORT, reason='cryptography module not found'
    )
    def test_201_key_parameter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=VAULT_V03_CONFIG,
        ):
            result = runner.invoke(
                exporter.derivepassphrase_export,
                ['-k', VAULT_MASTER_KEY, '.vault'],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == VAULT_V03_CONFIG_DATA

    @pytest.mark.xfail(
        not CRYPTOGRAPHY_SUPPORT, reason='cryptography module not found'
    )
    @pytest.mark.parametrize(
        ['version', 'config', 'config_data'],
        [
            pytest.param(
                '0.2', VAULT_V02_CONFIG, VAULT_V02_CONFIG_DATA, id='0.2'
            ),
            pytest.param(
                '0.3', VAULT_V03_CONFIG, VAULT_V03_CONFIG_DATA, id='0.3'
            ),
            pytest.param(
                'storeroom',
                VAULT_STOREROOM_CONFIG_ZIPPED,
                VAULT_STOREROOM_CONFIG_DATA,
                id='storeroom',
            ),
        ],
    )
    def test_210_load_vault_v02_v03_storeroom(
        self,
        monkeypatch: pytest.MonkeyPatch,
        version: str,
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
                exporter.derivepassphrase_export,
                [
                    '-f',
                    f'v{version}' if version.startswith('0') else version,
                    '-k',
                    VAULT_MASTER_KEY,
                    'VAULT_PATH',
                ],
            )
        assert not result.exception
        assert (result.exit_code, result.stderr_bytes) == (0, b'')
        assert json.loads(result.stdout) == config_data

    def test_300_invalid_format(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=VAULT_V03_CONFIG,
            vault_key=VAULT_MASTER_KEY,
        ):
            result = runner.invoke(
                exporter.derivepassphrase_export,
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

    @pytest.mark.xfail(
        not CRYPTOGRAPHY_SUPPORT, reason='cryptography module not found'
    )
    def test_301_vault_config_not_found(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=VAULT_V03_CONFIG,
            vault_key=VAULT_MASTER_KEY,
        ):
            result = runner.invoke(
                exporter.derivepassphrase_export,
                ['does-not-exist.txt'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert (
            b"Cannot parse 'does-not-exist.txt' as a valid config"
            in result.stderr_bytes
        )
        assert CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes

    @pytest.mark.xfail(
        not CRYPTOGRAPHY_SUPPORT, reason='cryptography module not found'
    )
    def test_302_vault_config_invalid(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config='',
            vault_key=VAULT_MASTER_KEY,
        ):
            result = runner.invoke(
                exporter.derivepassphrase_export,
                ['.vault'],
            )
        assert isinstance(result.exception, SystemExit)
        assert result.exit_code
        assert result.stderr_bytes
        assert (
            b"Cannot parse '.vault' as a valid config." in result.stderr_bytes
        )
        assert CANNOT_LOAD_CRYPTOGRAPHY not in result.stderr_bytes


class TestStoreroomExporter:
    pass  # TODO(the-13th-letter): Fill in once design is stable.


class TestV02Exporter:
    pass  # TODO(the-13th-letter): Fill in once design is stable.


class TestV03Exporter:
    pass  # TODO(the-13th-letter): Fill in once design is stable.
