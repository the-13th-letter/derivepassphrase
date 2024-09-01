# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import contextlib
import errno
import json
import os
import shutil
import socket
from typing import TYPE_CHECKING

import click.testing
import pytest
from typing_extensions import NamedTuple

import derivepassphrase as dpp
import tests
from derivepassphrase import _types, cli, ssh_agent

if TYPE_CHECKING:
    from collections.abc import Callable

    from typing_extensions import Any

DUMMY_SERVICE = tests.DUMMY_SERVICE
DUMMY_PASSPHRASE = tests.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = tests.DUMMY_CONFIG_SETTINGS
DUMMY_RESULT_PASSPHRASE = tests.DUMMY_RESULT_PASSPHRASE
DUMMY_RESULT_KEY1 = tests.DUMMY_RESULT_KEY1
DUMMY_PHRASE_FROM_KEY1_RAW = tests.DUMMY_PHRASE_FROM_KEY1_RAW
DUMMY_PHRASE_FROM_KEY1 = tests.DUMMY_PHRASE_FROM_KEY1

DUMMY_KEY1 = tests.DUMMY_KEY1
DUMMY_KEY1_B64 = tests.DUMMY_KEY1_B64
DUMMY_KEY2 = tests.DUMMY_KEY2
DUMMY_KEY2_B64 = tests.DUMMY_KEY2_B64
DUMMY_KEY3 = tests.DUMMY_KEY3
DUMMY_KEY3_B64 = tests.DUMMY_KEY3_B64


class IncompatibleConfiguration(NamedTuple):
    other_options: list[tuple[str, ...]]
    needs_service: bool | None
    input: str | None


class SingleConfiguration(NamedTuple):
    needs_service: bool | None
    input: str | None
    check_success: bool


class OptionCombination(NamedTuple):
    options: list[str]
    incompatible: bool
    needs_service: bool | None
    input: str | None
    check_success: bool


PASSWORD_GENERATION_OPTIONS: list[tuple[str, ...]] = [
    ('--phrase',),
    ('--key',),
    ('--length', '20'),
    ('--repeat', '20'),
    ('--lower', '1'),
    ('--upper', '1'),
    ('--number', '1'),
    ('--space', '1'),
    ('--dash', '1'),
    ('--symbol', '1'),
]
CONFIGURATION_OPTIONS: list[tuple[str, ...]] = [
    ('--notes',),
    ('--config',),
    ('--delete',),
    ('--delete-globals',),
    ('--clear',),
]
CONFIGURATION_COMMANDS: list[tuple[str, ...]] = [
    ('--notes',),
    ('--delete',),
    ('--delete-globals',),
    ('--clear',),
]
STORAGE_OPTIONS: list[tuple[str, ...]] = [('--export', '-'), ('--import', '-')]
INCOMPATIBLE: dict[tuple[str, ...], IncompatibleConfiguration] = {
    ('--phrase',): IncompatibleConfiguration(
        [('--key',), *CONFIGURATION_COMMANDS, *STORAGE_OPTIONS],
        True,
        DUMMY_PASSPHRASE,
    ),
    ('--key',): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--length', '20'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--repeat', '20'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--lower', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--upper', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--number', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--space', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--dash', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--symbol', '1'): IncompatibleConfiguration(
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, DUMMY_PASSPHRASE
    ),
    ('--notes',): IncompatibleConfiguration(
        [
            ('--config',),
            ('--delete',),
            ('--delete-globals',),
            ('--clear',),
            *STORAGE_OPTIONS,
        ],
        True,
        None,
    ),
    ('--config', '-p'): IncompatibleConfiguration(
        [('--delete',), ('--delete-globals',), ('--clear',), *STORAGE_OPTIONS],
        None,
        DUMMY_PASSPHRASE,
    ),
    ('--delete',): IncompatibleConfiguration(
        [('--delete-globals',), ('--clear',), *STORAGE_OPTIONS], True, None
    ),
    ('--delete-globals',): IncompatibleConfiguration(
        [('--clear',), *STORAGE_OPTIONS], False, None
    ),
    ('--clear',): IncompatibleConfiguration(STORAGE_OPTIONS, False, None),
    ('--export', '-'): IncompatibleConfiguration(
        [('--import', '-')], False, None
    ),
    ('--import', '-'): IncompatibleConfiguration([], False, None),
}
SINGLES: dict[tuple[str, ...], SingleConfiguration] = {
    ('--phrase',): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--key',): SingleConfiguration(True, None, False),
    ('--length', '20'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--repeat', '20'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--lower', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--upper', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--number', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--space', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--dash', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--symbol', '1'): SingleConfiguration(True, DUMMY_PASSPHRASE, True),
    ('--notes',): SingleConfiguration(True, None, False),
    ('--config', '-p'): SingleConfiguration(None, DUMMY_PASSPHRASE, False),
    ('--delete',): SingleConfiguration(True, None, False),
    ('--delete-globals',): SingleConfiguration(False, None, True),
    ('--clear',): SingleConfiguration(False, None, True),
    ('--export', '-'): SingleConfiguration(False, None, True),
    ('--import', '-'): SingleConfiguration(False, '{"services": {}}', True),
}
INTERESTING_OPTION_COMBINATIONS: list[OptionCombination] = []
config: IncompatibleConfiguration | SingleConfiguration
for opt, config in INCOMPATIBLE.items():
    for opt2 in config.other_options:
        INTERESTING_OPTION_COMBINATIONS.extend([
            OptionCombination(
                options=list(opt + opt2),
                incompatible=True,
                needs_service=config.needs_service,
                input=config.input,
                check_success=False,
            ),
            OptionCombination(
                options=list(opt2 + opt),
                incompatible=True,
                needs_service=config.needs_service,
                input=config.input,
                check_success=False,
            ),
        ])
for opt, config in SINGLES.items():
    INTERESTING_OPTION_COMBINATIONS.append(
        OptionCombination(
            options=list(opt),
            incompatible=False,
            needs_service=config.needs_service,
            input=config.input,
            check_success=config.check_success,
        )
    )


class TestCLI:
    def test_200_help_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase, ['--help'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True, output='Password generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use NUMBER=0, e.g. "--symbol 0"'
        ), 'expected clean exit, and option group epilog in help text'

    @pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    def test_201_disable_character_set(
        self, monkeypatch: pytest.MonkeyPatch, charset_name: str
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        option = f'--{charset_name}'
        charset = dpp.vault.Vault._CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                [option, '0', '-p', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit:'
        for c in charset:
            assert (
                c not in result.output
            ), f'derived password contains forbidden character {c!r}'

    def test_202_disable_repetition(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--repeat', '0', '-p', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True
        ), 'expected clean exit and empty stderr'
        passphrase = result.output.rstrip('\r\n')
        for i in range(len(passphrase) - 1):
            assert passphrase[i : i + 1] != passphrase[i + 1 : i + 2], (
                f'derived password contains repeated character '
                f'at position {i}: {result.output!r}'
            )

    @pytest.mark.parametrize(
        'config',
        [
            pytest.param(
                {
                    'global': {'key': DUMMY_KEY1_B64},
                    'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS},
                },
                id='global',
            ),
            pytest.param(
                {
                    'global': {'phrase': DUMMY_PASSPHRASE.rstrip('\n')},
                    'services': {
                        DUMMY_SERVICE: {
                            'key': DUMMY_KEY1_B64,
                            **DUMMY_CONFIG_SETTINGS,
                        }
                    },
                },
                id='service',
            ),
        ],
    )
    def test_204a_key_from_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config: _types.VaultConfig,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config=config
        ):
            monkeypatch.setattr(
                dpp.vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            _result = runner.invoke(
                cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True
        ), 'expected clean exit and empty stderr'
        assert _result.stdout_bytes
        assert (
            _result.stdout_bytes.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE
        ), 'known false output: phrase-based instead of key-based'
        assert (
            _result.stdout_bytes.rstrip(b'\n') == DUMMY_RESULT_KEY1
        ), 'expected known output'

    def test_204b_key_from_command_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            monkeypatch.setattr(
                dpp.vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            _result = runner.invoke(
                cli.derivepassphrase,
                ['-k', DUMMY_SERVICE],
                input='1\n',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert _result.stdout_bytes, 'expected program output'
        last_line = _result.stdout_bytes.splitlines(True)[-1]
        assert (
            last_line.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE
        ), 'known false output: phrase-based instead of key-based'
        assert (
            last_line.rstrip(b'\n') == DUMMY_RESULT_KEY1
        ), 'expected known output'

    @tests.skip_if_no_agent
    @pytest.mark.parametrize(
        'config',
        [
            pytest.param(
                {
                    'global': {'key': DUMMY_KEY1_B64},
                    'services': {DUMMY_SERVICE: {}},
                },
                id='global_config',
            ),
            pytest.param(
                {'services': {DUMMY_SERVICE: {'key': DUMMY_KEY2_B64}}},
                id='service_config',
            ),
            pytest.param(
                {
                    'global': {'key': DUMMY_KEY1_B64},
                    'services': {DUMMY_SERVICE: {'key': DUMMY_KEY2_B64}},
                },
                id='full_config',
            ),
        ],
    )
    @pytest.mark.parametrize('key_index', [1, 2, 3], ids=lambda i: f'index{i}')
    def test_204c_key_override_on_command_line(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config: dict[str, Any],
        key_index: int,
    ) -> None:
        def sign(
            _: Any, key: bytes | bytearray, message: bytes | bytearray
        ) -> bytes:
            del message  # Unused.
            for value in tests.SUPPORTED_KEYS.values():
                if value['public_key_data'] == key:
                    assert value['expected_signature'] is not None
                    return value['expected_signature']
            raise AssertionError

        monkeypatch.setattr(
            ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
        )
        monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', sign)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config=config
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['-k', DUMMY_SERVICE],
                input=f'{key_index}\n',
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert result.output, 'expected program output'
        assert result.stderr, 'expected stderr'
        assert (
            'Error:' not in result.stderr
        ), 'expected no error messages on stderr'

    def test_205_service_phrase_if_key_in_global_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={
                'global': {'key': DUMMY_KEY1_B64},
                'services': {
                    DUMMY_SERVICE: {
                        'phrase': DUMMY_PASSPHRASE.rstrip('\n'),
                        **DUMMY_CONFIG_SETTINGS,
                    }
                },
            },
        ):
            _result = runner.invoke(
                cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert _result.stdout_bytes, 'expected program output'
        last_line = _result.stdout_bytes.splitlines(True)[-1]
        assert (
            last_line.rstrip(b'\n') != DUMMY_RESULT_KEY1
        ), 'known false output: key-based instead of phrase-based'
        assert (
            last_line.rstrip(b'\n') == DUMMY_RESULT_PASSPHRASE
        ), 'expected known output'

    @pytest.mark.parametrize(
        'option',
        [
            '--lower',
            '--upper',
            '--number',
            '--space',
            '--dash',
            '--symbol',
            '--repeat',
            '--length',
        ],
    )
    def test_210_invalid_argument_range(
        self, monkeypatch: pytest.MonkeyPatch, option: str
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            for value in '-42', 'invalid':
                _result = runner.invoke(
                    cli.derivepassphrase,
                    [option, value, '-p', DUMMY_SERVICE],
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(_result)
                assert result.error_exit(
                    error='Error: Invalid value'
                ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        ['options', 'service', 'input', 'check_success'],
        [
            (o.options, o.needs_service, o.input, o.check_success)
            for o in INTERESTING_OPTION_COMBINATIONS
            if not o.incompatible
        ],
    )
    def test_211_service_needed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        options: list[str],
        service: bool | None,
        input: str | None,
        check_success: bool,
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                options if service else [*options, DUMMY_SERVICE],
                input=input,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            if service is not None:
                err_msg = (
                    ' requires a SERVICE'
                    if service
                    else ' does not take a SERVICE argument'
                )
                assert result.error_exit(
                    error=err_msg
                ), 'expected error exit and known error message'
            else:
                assert result.clean_exit(
                    empty_stderr=True
                ), 'expected clean exit'
        if check_success:
            with tests.isolated_config(
                monkeypatch=monkeypatch,
                runner=runner,
                config={'global': {'phrase': 'abc'}, 'services': {}},
            ):
                monkeypatch.setattr(
                    cli, '_prompt_for_passphrase', tests.auto_prompt
                )
                _result = runner.invoke(
                    cli.derivepassphrase,
                    [*options, DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    @pytest.mark.parametrize(
        ['options', 'service'],
        [
            (o.options, o.needs_service)
            for o in INTERESTING_OPTION_COMBINATIONS
            if o.incompatible
        ],
    )
    def test_212_incompatible_options(
        self,
        monkeypatch: pytest.MonkeyPatch,
        options: list[str],
        service: bool | None,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                [*options, DUMMY_SERVICE] if service else options,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='mutually exclusive with '
        ), 'expected error exit and known error message'

    def test_213_import_bad_config_not_vault_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--import', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Invalid vault config'
        ), 'expected error exit and known error message'

    def test_213a_import_bad_config_not_json_data(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--import', '-'],
                input='This string is not valid JSON.',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='cannot decode JSON'
        ), 'expected error exit and known error message'

    def test_213b_import_bad_config_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        # `isolated_config` validates the configuration.  So, to pass an
        # actual broken configuration, we must open the configuration file
        # ourselves afterwards, inside the context.
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with open(
                cli._config_filename(), 'w', encoding='UTF-8'
            ) as outfile:
                print('This string is not valid JSON.', file=outfile)
            dname = os.path.dirname(cli._config_filename())
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--import', os.fsdecode(dname)],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=os.strerror(errno.EISDIR)
        ), 'expected error exit and known error message'

    def test_214_export_settings_no_stored_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename())
            _result = runner.invoke(
                cli.derivepassphrase, ['--export', '-'], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    def test_214a_export_settings_bad_stored_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={}
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--export', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ), 'expected error exit and known error message'

    def test_214b_export_settings_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename())
            os.makedirs(cli._config_filename())
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--export', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ), 'expected error exit and known error message'

    def test_214c_export_settings_target_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            dname = os.path.dirname(cli._config_filename())
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--export', os.fsdecode(dname)],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot store config'
        ), 'expected error exit and known error message'

    def test_214d_export_settings_settings_directory_not_a_directory(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree('.derivepassphrase')
            with open('.derivepassphrase', 'w', encoding='UTF-8') as outfile:
                print('Obstruction!!', file=outfile)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--export', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ), 'expected error exit and known error message'

    def test_220_edit_notes_successfully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        edit_result = """

# - - - - - >8 - - - - - >8 - - - - - >8 - - - - - >8 - - - - -
contents go here
"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: edit_result)  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'contents go here'}},
            }

    def test_221_edit_notes_noop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: None)  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    def test_222_edit_notes_marker_removed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: 'long\ntext')  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'long\ntext'}},
            }

    def test_223_edit_notes_abort(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: '\n\n')  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='user aborted request'
            ), 'expected known error message'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    @pytest.mark.parametrize(
        ['command_line', 'input', 'result_config'],
        [
            (
                ['--phrase'],
                'my passphrase\n',
                {'global': {'phrase': 'my passphrase'}, 'services': {}},
            ),
            (
                ['--key'],
                '1\n',
                {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            ),
            (
                ['--phrase', 'sv'],
                'my passphrase\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'phrase': 'my passphrase'}},
                },
            ),
            (
                ['--key', 'sv'],
                '1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64}},
                },
            ),
            (
                ['--key', '--length', '15', 'sv'],
                '1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
                },
            ),
        ],
    )
    def test_224_store_config_good(
        self,
        monkeypatch: pytest.MonkeyPatch,
        command_line: list[str],
        input: str,
        result_config: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(), 'expected clean exit'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert (
                config == result_config
            ), 'stored config does not match expectation'

    @pytest.mark.parametrize(
        ['command_line', 'input', 'err_text'],
        [
            ([], '', 'Cannot update global settings without actual settings'),
            (
                ['sv'],
                '',
                'Cannot update service settings without actual settings',
            ),
            (['--phrase', 'sv'], '', 'No passphrase given'),
            (['--key'], '', 'No valid SSH key selected'),
        ],
    )
    def test_225_store_config_fail(
        self,
        monkeypatch: pytest.MonkeyPatch,
        command_line: list[str],
        input: str,
        err_text: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=err_text
        ), 'expected error exit and known error message'

    def test_225a_store_config_fail_manual_no_ssh_key_selection(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            custom_error = 'custom error message'

            def raiser() -> None:
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_select_ssh_key', raiser)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=custom_error
        ), 'expected error exit and known error message'

    def test_225b_store_config_fail_manual_no_ssh_agent(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot find running SSH agent'
        ), 'expected error exit and known error message'

    def test_225c_store_config_fail_manual_bad_ssh_agent_connection(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setenv('SSH_AUTH_SOCK', os.getcwd())
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot connect to SSH agent'
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize('try_race_free_implementation', [True, False])
    def test_225d_store_config_fail_manual_read_only_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        try_race_free_implementation: bool,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            tests.make_file_readonly(
                cli._config_filename(),
                try_race_free_implementation=try_race_free_implementation,
            )
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', '--length=15', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot store config'
        ), 'expected error exit and known error message'

    def test_225e_store_config_fail_manual_custom_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            custom_error = 'custom error message'

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_save_config', raiser)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', '--length=15', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=custom_error
        ), 'expected error exit and known error message'

    def test_226_no_arguments(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase, [], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='SERVICE is required'
        ), 'expected error exit and known error message'

    def test_226a_no_passphrase_or_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='No passphrase or key given'
        ), 'expected error exit and known error message'

    def test_230_config_directory_nonexistant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """the-13th-letter/derivepassphrase#6"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            os.remove('.derivepassphrase/settings.json')
            os.rmdir('.derivepassphrase')
            os_makedirs_called = False
            real_os_makedirs = os.makedirs

            def makedirs(*args: Any, **kwargs: Any) -> Any:
                nonlocal os_makedirs_called
                os_makedirs_called = True
                return real_os_makedirs(*args, **kwargs)

            monkeypatch.setattr(os, 'makedirs', makedirs)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(), 'expected clean exit'
            assert (
                result.stderr == 'Passphrase:'
            ), 'program unexpectedly failed?!'
            assert os_makedirs_called, 'os.makedirs has not been called?!'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config_readback = json.load(infile)
            assert config_readback == {
                'global': {'phrase': 'abc'},
                'services': {},
            }, 'config mismatch'

    def test_230a_config_directory_not_a_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """the-13th-letter/derivepassphrase#6"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _save_config = cli._save_config

            def obstruct_config_saving(*args: Any, **kwargs: Any) -> Any:
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree('.derivepassphrase')
                with open(
                    '.derivepassphrase', 'w', encoding='UTF-8'
                ) as outfile:
                    print('Obstruction!!', file=outfile)
                monkeypatch.setattr(cli, '_save_config', _save_config)
                return _save_config(*args, **kwargs)

            monkeypatch.setattr(cli, '_save_config', obstruct_config_saving)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='Cannot store config'
            ), 'expected error exit and known error message'

    def test_230b_store_config_custom_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {}},
        ):
            _save_config = cli._save_config

            def obstruct_config_saving(*args: Any, **kwargs: Any) -> Any:
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree('.derivepassphrase')
                with open(
                    '.derivepassphrase', 'w', encoding='UTF-8'
                ) as outfile:
                    print('Obstruction!!', file=outfile)
                monkeypatch.setattr(cli, '_save_config', _save_config)
                return _save_config(*args, **kwargs)

            monkeypatch.setattr(cli, '_save_config', obstruct_config_saving)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='Cannot store config'
            ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        ['command_line', 'input', 'warning_message'],
        [
            pytest.param(
                ['--import', '-'],
                json.dumps({
                    'global': {'phrase': 'Du\u0308sseldorf'},
                    'services': {},
                }),
                'the global passphrase is not NFC-normalized',
                id='global-NFC',
            ),
            pytest.param(
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'weird entry name': {'phrase': 'Du\u0308sseldorf'},
                    }
                }),
                (
                    "the services.'weird entry name' passphrase "
                    'is not NFC-normalized'
                ),
                id='service-weird-name-NFC',
            ),
            pytest.param(
                ['--config', '-p', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                (
                    f'the services.{DUMMY_SERVICE} passphrase '
                    f'is not NFC-normalized'
                ),
                id='config-NFC',
            ),
            pytest.param(
                ['-p', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                'the interactive passphrase is not NFC-normalized',
                id='direct-input-NFC',
            ),
            pytest.param(
                ['--import', '-'],
                json.dumps({
                    'global': {
                        'unicode_normalization_form': 'NFD',
                        'phrase': 'D\u00fcsseldorf',
                    },
                    'services': {},
                }),
                'the global passphrase is not NFD-normalized',
                id='global-NFD',
            ),
            pytest.param(
                ['--import', '-'],
                json.dumps({
                    'global': {
                        'unicode_normalization_form': 'NFD',
                    },
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'weird entry name': {'phrase': 'D\u00fcsseldorf'},
                    },
                }),
                (
                    "the services.'weird entry name' passphrase "
                    'is not NFD-normalized'
                ),
                id='service-weird-name-NFD',
            ),
        ],
    )
    def test_300_unicode_normalization_form_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        command_line: list[str],
        input: str | None,
        warning_message: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                command_line,
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert (
            warning_message in result.stderr
        ), 'expected known warning message in stderr'


class TestCLIUtils:
    def test_100_save_bad_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner()
        with (
            tests.isolated_config(
                monkeypatch=monkeypatch, runner=runner, config={}
            ),
            pytest.raises(ValueError, match='Invalid vault config'),
        ):
            cli._save_config(None)  # type: ignore[arg-type]

    def test_101_prompt_for_selection_multiple(self) -> None:
        @click.command()
        @click.option('--heading', default='Our menu:')
        @click.argument('items', nargs=-1)
        def driver(heading: str, items: list[str]) -> None:
            # from https://montypython.fandom.com/wiki/Spam#The_menu
            items = items or [
                'Egg and bacon',
                'Egg, sausage and bacon',
                'Egg and spam',
                'Egg, bacon and spam',
                'Egg, bacon, sausage and spam',
                'Spam, bacon, sausage and spam',
                'Spam, egg, spam, spam, bacon and spam',
                'Spam, spam, spam, egg and spam',
                (
                    'Spam, spam, spam, spam, spam, spam, baked beans, '
                    'spam, spam, spam and spam'
                ),
                (
                    'Lobster thermidor aux crevettes with a mornay sauce '
                    'garnished with truffle paté, brandy '
                    'and a fried egg on top and spam'
                ),
            ]
            index = cli._prompt_for_selection(items, heading=heading)
            click.echo('A fine choice: ', nl=False)
            click.echo(items[index])
            click.echo('(Note: Vikings strictly optional.)')

        runner = click.testing.CliRunner(mix_stderr=True)
        _result = runner.invoke(driver, [], input='9')
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            output="""\
Our menu:
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort): 9
A fine choice: Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
(Note: Vikings strictly optional.)
"""  # noqa: E501
        ), 'expected clean exit'
        _result = runner.invoke(
            driver, ['--heading='], input='', catch_exceptions=True
        )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=IndexError
        ), 'expected error exit and known error type'
        assert (
            result.output
            == """\
[1] Egg and bacon
[2] Egg, sausage and bacon
[3] Egg and spam
[4] Egg, bacon and spam
[5] Egg, bacon, sausage and spam
[6] Spam, bacon, sausage and spam
[7] Spam, egg, spam, spam, bacon and spam
[8] Spam, spam, spam, egg and spam
[9] Spam, spam, spam, spam, spam, spam, baked beans, spam, spam, spam and spam
[10] Lobster thermidor aux crevettes with a mornay sauce garnished with truffle paté, brandy and a fried egg on top and spam
Your selection? (1-10, leave empty to abort):\x20
"""  # noqa: E501
        ), 'expected known output'

    def test_102_prompt_for_selection_single(self) -> None:
        @click.command()
        @click.option('--item', default='baked beans')
        @click.argument('prompt')
        def driver(item: str, prompt: str) -> None:
            try:
                cli._prompt_for_selection(
                    [item], heading='', single_choice_prompt=prompt
                )
            except IndexError:
                click.echo('Boo.')
                raise
            else:
                click.echo('Great!')

        runner = click.testing.CliRunner(mix_stderr=True)
        _result = runner.invoke(
            driver, ['Will replace with spam. Confirm, y/n?'], input='y'
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            output="""\
[1] baked beans
Will replace with spam. Confirm, y/n? y
Great!
"""
        ), 'expected clean exit'
        _result = runner.invoke(
            driver,
            ['Will replace with spam, okay? ' '(Please say "y" or "n".)'],
            input='',
        )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=IndexError
        ), 'expected error exit and known error type'
        assert (
            result.output
            == """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".):\x20
Boo.
"""
        ), 'expected known output'

    def test_103_prompt_for_passphrase(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            click,
            'prompt',
            lambda *a, **kw: json.dumps({'args': a, 'kwargs': kw}),
        )
        res = json.loads(cli._prompt_for_passphrase())
        err_msg = 'missing arguments to passphrase prompt'
        assert 'args' in res, err_msg
        assert 'kwargs' in res, err_msg
        assert res['args'][:1] == ['Passphrase'], err_msg
        assert res['kwargs'].get('default') == '', err_msg
        assert not res['kwargs'].get('show_default', True), err_msg
        assert res['kwargs'].get('err'), err_msg
        assert res['kwargs'].get('hide_input'), err_msg

    @pytest.mark.parametrize(
        ['command_line', 'config', 'result_config'],
        [
            (
                ['--delete-globals'],
                {'global': {'phrase': 'abc'}, 'services': {}},
                {'services': {}},
            ),
            (
                ['--delete', DUMMY_SERVICE],
                {
                    'global': {'phrase': 'abc'},
                    'services': {DUMMY_SERVICE: {'notes': '...'}},
                },
                {'global': {'phrase': 'abc'}, 'services': {}},
            ),
            (
                ['--clear'],
                {
                    'global': {'phrase': 'abc'},
                    'services': {DUMMY_SERVICE: {'notes': '...'}},
                },
                {'services': {}},
            ),
        ],
    )
    def test_203_repeated_config_deletion(
        self,
        monkeypatch: pytest.MonkeyPatch,
        command_line: list[str],
        config: _types.VaultConfig,
        result_config: _types.VaultConfig,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        for start_config in [config, result_config]:
            with tests.isolated_config(
                monkeypatch=monkeypatch, runner=runner, config=start_config
            ):
                _result = runner.invoke(
                    cli.derivepassphrase, command_line, catch_exceptions=False
                )
                result = tests.ReadableResult.parse(_result)
                assert result.clean_exit(
                    empty_stderr=True
                ), 'expected clean exit'
                with open(cli._config_filename(), encoding='UTF-8') as infile:
                    config_readback = json.load(infile)
                assert config_readback == result_config

    def test_204_phrase_from_key_manually(self) -> None:
        assert (
            dpp.vault.Vault(
                phrase=DUMMY_PHRASE_FROM_KEY1, **DUMMY_CONFIG_SETTINGS
            ).generate(DUMMY_SERVICE)
            == DUMMY_RESULT_KEY1
        )

    @pytest.mark.parametrize(
        ['vfunc', 'input'],
        [
            (cli._validate_occurrence_constraint, 20),
            (cli._validate_length, 20),
        ],
    )
    def test_210a_validate_constraints_manually(
        self,
        vfunc: Callable[[click.Context, click.Parameter, Any], int | None],
        input: int,
    ) -> None:
        ctx = cli.derivepassphrase.make_context(cli.PROG_NAME, [])
        param = cli.derivepassphrase.params[0]
        assert vfunc(ctx, param, input) == input

    @tests.skip_if_no_agent
    @pytest.mark.parametrize('conn_hint', ['none', 'socket', 'client'])
    def test_227_get_suitable_ssh_keys(
        self,
        monkeypatch: pytest.MonkeyPatch,
        conn_hint: str,
    ) -> None:
        monkeypatch.setattr(
            ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
        )
        hint: ssh_agent.SSHAgentClient | socket.socket | None
        match conn_hint:
            case 'client':
                hint = ssh_agent.SSHAgentClient()
            case 'socket':
                hint = socket.socket(family=socket.AF_UNIX)
                hint.connect(os.environ['SSH_AUTH_SOCK'])
            case _:
                assert conn_hint == 'none'
                hint = None
        exception: Exception | None = None
        try:
            list(cli._get_suitable_ssh_keys(hint))
        except RuntimeError:  # pragma: no cover
            pass
        except Exception as e:  # noqa: BLE001 # pragma: no cover
            exception = e
        finally:
            assert exception is None, 'exception querying suitable SSH keys'
