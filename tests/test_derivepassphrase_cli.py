# SPDX-FileCopyrightText: 2024 Marco Ricci <m@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import contextlib
import json
import os
import socket
from typing import TYPE_CHECKING, cast

import click.testing
import pytest
from typing_extensions import NamedTuple

import derivepassphrase as dpp
import ssh_agent_client
import tests
from derivepassphrase import cli

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


class IncompatibleConfiguration(NamedTuple):
    other_options: list[tuple[str, ...]]
    needs_service: bool | None
    input: bytes | None


class SingleConfiguration(NamedTuple):
    needs_service: bool | None
    input: bytes | None
    check_success: bool


class OptionCombination(NamedTuple):
    options: list[str]
    incompatible: bool
    needs_service: bool | None
    input: bytes | None
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
    ('--import', '-'): SingleConfiguration(False, b'{"services": {}}', True),
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
    def test_200_help_output(self):
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase, ['--help'], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert (
            'Password generation:\n' in result.output
        ), 'Option groups not respected in help text.'
        assert (
            'Use NUMBER=0, e.g. "--symbol 0"' in result.output
        ), 'Option group epilog not printed.'

    @pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    def test_201_disable_character_set(
        self, monkeypatch: Any, charset_name: str
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        option = f'--{charset_name}'
        charset = dpp.Vault._CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase,
            [option, '0', '-p', DUMMY_SERVICE],
            input=DUMMY_PASSPHRASE,
            catch_exceptions=False,
        )
        assert (
            result.exit_code == 0
        ), f'program died unexpectedly with exit code {result.exit_code}'
        assert (
            not result.stderr_bytes
        ), f'program barfed on stderr: {result.stderr_bytes!r}'
        for c in charset:
            assert c not in result.stdout, (
                f'derived password contains forbidden character {c!r}: '
                f'{result.stdout!r}'
            )

    def test_202_disable_repetition(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase,
            ['--repeat', '0', '-p', DUMMY_SERVICE],
            input=DUMMY_PASSPHRASE,
            catch_exceptions=False,
        )
        assert (
            result.exit_code == 0
        ), f'program died unexpectedly with exit code {result.exit_code}'
        assert (
            not result.stderr_bytes
        ), f'program barfed on stderr: {result.stderr_bytes!r}'
        passphrase = result.stdout.rstrip('\r\n')
        for i in range(len(passphrase) - 1):
            assert passphrase[i : i + 1] != passphrase[i + 1 : i + 2], (
                f'derived password contains repeated character '
                f'at position {i}: {result.stdout!r}'
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
                    'global': {
                        'phrase': DUMMY_PASSPHRASE.rstrip(b'\n').decode(
                            'ASCII'
                        )
                    },
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
        monkeypatch: Any,
        config: dpp.types.VaultConfig,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config=config
        ):
            monkeypatch.setattr(
                dpp.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            result = runner.invoke(
                cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
            )
            assert (result.exit_code, result.stderr_bytes) == (
                0,
                b'',
            ), 'program exited with failure'
            assert (
                result.stdout_bytes.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE
            ), 'program generated unexpected result (phrase instead of key)'
            assert (
                result.stdout_bytes.rstrip(b'\n') == DUMMY_RESULT_KEY1
            ), 'program generated unexpected result (wrong settings?)'

    def test_204b_key_from_command_line(self, monkeypatch: Any) -> None:
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
                dpp.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            result = runner.invoke(
                cli.derivepassphrase,
                ['-k', DUMMY_SERVICE],
                input=b'1\n',
                catch_exceptions=False,
            )
            assert result.exit_code == 0, 'program exited with failure'
            assert result.stdout_bytes, 'program output expected'
            last_line = result.stdout_bytes.splitlines(True)[-1]
            assert (
                last_line.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE
            ), 'program generated unexpected result (phrase instead of key)'
            assert (
                last_line.rstrip(b'\n') == DUMMY_RESULT_KEY1
            ), 'program generated unexpected result (wrong settings?)'

    def test_205_service_phrase_if_key_in_global_config(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={
                'global': {'key': DUMMY_KEY1_B64},
                'services': {
                    DUMMY_SERVICE: {
                        'phrase': DUMMY_PASSPHRASE.rstrip(b'\n').decode(
                            'ASCII'
                        ),
                        **DUMMY_CONFIG_SETTINGS,
                    }
                },
            },
        ):
            result = runner.invoke(
                cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
            )
            assert result.exit_code == 0, 'program exited with failure'
            assert result.stdout_bytes, 'program output expected'
            last_line = result.stdout_bytes.splitlines(True)[-1]
            assert (
                last_line.rstrip(b'\n') != DUMMY_RESULT_KEY1
            ), 'program generated unexpected result (key instead of phrase)'
            assert (
                last_line.rstrip(b'\n') == DUMMY_RESULT_PASSPHRASE
            ), 'program generated unexpected result (wrong settings?)'

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
    def test_210_invalid_argument_range(self, option: str) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        value: str | int
        for value in '-42', 'invalid':
            result = runner.invoke(
                cli.derivepassphrase,
                [option, cast(str, value), '-p', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'Error: Invalid value' in result.stderr_bytes
            ), 'program did not print the expected error message'

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
        monkeypatch: Any,
        options: list[str],
        service: bool | None,
        input: bytes | None,
        check_success: bool,
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            result = runner.invoke(
                cli.derivepassphrase,
                options if service else [*options, DUMMY_SERVICE],
                input=input,
                catch_exceptions=False,
            )
            if service is not None:
                assert result.exit_code > 0, 'program unexpectedly succeeded'
                assert (
                    result.stderr_bytes
                ), 'program did not print any error message'
                err_msg = (
                    b' requires a SERVICE'
                    if service
                    else b' does not take a SERVICE argument'
                )
                assert (
                    err_msg in result.stderr_bytes
                ), 'program did not print the expected error message'
            else:
                assert (result.exit_code, result.stderr_bytes) == (
                    0,
                    b'',
                ), 'program unexpectedly failed'
        if check_success:
            with tests.isolated_config(
                monkeypatch=monkeypatch,
                runner=runner,
                config={'global': {'phrase': 'abc'}, 'services': {}},
            ):
                monkeypatch.setattr(
                    cli, '_prompt_for_passphrase', tests.auto_prompt
                )
                result = runner.invoke(
                    cli.derivepassphrase,
                    [*options, DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
                assert (result.exit_code, result.stderr_bytes) == (
                    0,
                    b'',
                ), 'program unexpectedly failed'

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
        options: list[str],
        service: bool | None,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase,
            [*options, DUMMY_SERVICE] if service else options,
            input=DUMMY_PASSPHRASE,
            catch_exceptions=False,
        )
        assert result.exit_code > 0, 'program unexpectedly succeeded'
        assert result.stderr_bytes, 'program did not print any error message'
        assert (
            b'mutually exclusive with ' in result.stderr_bytes
        ), 'program did not print the expected error message'

    def test_213_import_bad_config_not_vault_config(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            result = runner.invoke(
                cli.derivepassphrase,
                ['--import', '-'],
                input=b'null',
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'not a valid config' in result.stderr_bytes
            ), 'program did not print the expected error message'

    def test_213a_import_bad_config_not_json_data(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            result = runner.invoke(
                cli.derivepassphrase,
                ['--import', '-'],
                input=b'This string is not valid JSON.',
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'cannot decode JSON' in result.stderr_bytes
            ), 'program did not print the expected error message'

    def test_213b_import_bad_config_not_a_file(
        self,
        monkeypatch: Any,
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['--import', os.fsdecode(dname)],
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            # Don't test the actual error message, because it is subject to
            # locale settings.  TODO: find a way anyway.

    def test_214_export_settings_no_stored_settings(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename())
            result = runner.invoke(
                cli.derivepassphrase, ['--export', '-'], catch_exceptions=False
            )
            assert (result.exit_code, result.stderr_bytes) == (
                0,
                b'',
            ), 'program exited with failure'

    def test_214a_export_settings_bad_stored_config(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={}
        ):
            result = runner.invoke(
                cli.derivepassphrase,
                ['--export', '-'],
                input=b'null',
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'cannot load config' in result.stderr_bytes
            ), 'program did not print the expected error message'

    def test_214b_export_settings_not_a_file(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename())
            os.makedirs(cli._config_filename())
            result = runner.invoke(
                cli.derivepassphrase,
                ['--export', '-'],
                input=b'null',
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'cannot load config' in result.stderr_bytes
            ), 'program did not print the expected error message'

    def test_214c_export_settings_target_not_a_file(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch, runner=runner, config={'services': {}}
        ):
            dname = os.path.dirname(cli._config_filename())
            result = runner.invoke(
                cli.derivepassphrase,
                ['--export', os.fsdecode(dname)],
                input=b'null',
                catch_exceptions=False,
            )
            assert result.exit_code > 0, 'program unexpectedly succeeded'
            assert (
                result.stderr_bytes
            ), 'program did not print any error message'
            assert (
                b'cannot write config' in result.stderr_bytes
            ), 'program did not print the expected error message'

    def test_220_edit_notes_successfully(self, monkeypatch: Any) -> None:
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
            result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            assert (result.exit_code, result.stderr_bytes) == (
                0,
                b'',
            ), 'program exited with failure'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'contents go here'}},
            }

    def test_221_edit_notes_noop(self, monkeypatch: Any) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: None)  # noqa: ARG005
            result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            assert (result.exit_code, result.stderr_bytes) == (
                0,
                b'',
            ), 'program exited with failure'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    def test_222_edit_notes_marker_removed(self, monkeypatch: Any) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: 'long\ntext')  # noqa: ARG005
            result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            assert (result.exit_code, result.stderr_bytes) == (
                0,
                b'',
            ), 'program exited with failure'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'long\ntext'}},
            }

    def test_223_edit_notes_abort(self, monkeypatch: Any) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: '\n\n')  # noqa: ARG005
            result = runner.invoke(
                cli.derivepassphrase, ['--notes', 'sv'], catch_exceptions=False
            )
            assert result.exit_code != 0, 'program unexpectedly succeeded'
            assert result.stderr_bytes is not None
            assert (
                b'user aborted request' in result.stderr_bytes
            ), 'expected error message missing'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    @pytest.mark.parametrize(
        ['command_line', 'input', 'result_config'],
        [
            (
                ['--phrase'],
                b'my passphrase\n',
                {'global': {'phrase': 'my passphrase'}, 'services': {}},
            ),
            (
                ['--key'],
                b'1\n',
                {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            ),
            (
                ['--phrase', 'sv'],
                b'my passphrase\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'phrase': 'my passphrase'}},
                },
            ),
            (
                ['--key', 'sv'],
                b'1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64}},
                },
            ),
            (
                ['--key', '--length', '15', 'sv'],
                b'1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
                },
            ),
        ],
    )
    def test_224_store_config_good(
        self,
        monkeypatch: Any,
        command_line: list[str],
        input: bytes,
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            assert result.exit_code == 0, 'program exited with failure'
            with open(cli._config_filename(), encoding='UTF-8') as infile:
                config = json.load(infile)
            assert (
                config == result_config
            ), 'stored config does not match expectation'

    @pytest.mark.parametrize(
        ['command_line', 'input', 'err_text'],
        [
            (
                [],
                b'',
                b'cannot update global settings without actual settings',
            ),
            (
                ['sv'],
                b'',
                b'cannot update service settings without actual settings',
            ),
            (['--phrase', 'sv'], b'', b'no passphrase given'),
            (['--key'], b'', b'no valid SSH key selected'),
        ],
    )
    def test_225_store_config_fail(
        self,
        monkeypatch: Any,
        command_line: list[str],
        input: bytes,
        err_text: bytes,
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            assert result.exit_code != 0, 'program unexpectedly succeeded?!'
            assert result.stderr_bytes is not None
            assert (
                err_text in result.stderr_bytes
            ), 'expected error message missing'

    def test_225a_store_config_fail_manual_no_ssh_key_selection(
        self,
        monkeypatch: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
            config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            custom_error = 'custom error message'

            def raiser():
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_select_ssh_key', raiser)
            result = runner.invoke(
                cli.derivepassphrase,
                ['--key', '--config'],
                catch_exceptions=False,
            )
            assert result.exit_code != 0, 'program unexpectedly succeeded'
            assert result.stderr_bytes is not None
            assert (
                custom_error.encode() in result.stderr_bytes
            ), 'expected error message missing'

    def test_226_no_arguments(self) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase, [], catch_exceptions=False
        )
        assert result.exit_code != 0, 'program unexpectedly succeeded'
        assert result.stderr_bytes is not None
        assert (
            b'SERVICE is required' in result.stderr_bytes
        ), 'expected error message missing'

    def test_226a_no_passphrase_or_key(self) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli.derivepassphrase, [DUMMY_SERVICE], catch_exceptions=False
        )
        assert result.exit_code != 0, 'program unexpectedly succeeded'
        assert result.stderr_bytes is not None
        assert (
            b'no passphrase or key given' in result.stderr_bytes
        ), 'expected error message missing'


class TestCLIUtils:
    def test_100_save_bad_config(self, monkeypatch: Any) -> None:
        runner = click.testing.CliRunner()
        with (
            tests.isolated_config(
                monkeypatch=monkeypatch, runner=runner, config={}
            ),
            pytest.raises(ValueError, match='Invalid vault config'),
        ):
            cli._save_config(None)  # type: ignore

    def test_101_prompt_for_selection_multiple(self) -> None:
        @click.command()
        @click.option('--heading', default='Our menu:')
        @click.argument('items', nargs=-1)
        def driver(heading, items):
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
        result = runner.invoke(driver, [], input='9')
        assert result.exit_code == 0, 'driver program failed'
        assert (
            result.stdout
            == """\
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
        ), 'driver program produced unexpected output'
        result = runner.invoke(
            driver, ['--heading='], input='', catch_exceptions=True
        )
        assert result.exit_code > 0, 'driver program succeeded?!'
        assert (
            result.stdout
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
        ), 'driver program produced unexpected output'
        assert isinstance(
            result.exception, IndexError
        ), 'driver program did not raise IndexError?!'

    def test_102_prompt_for_selection_single(self) -> None:
        @click.command()
        @click.option('--item', default='baked beans')
        @click.argument('prompt')
        def driver(item, prompt):
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
        result = runner.invoke(
            driver, ['Will replace with spam. Confirm, y/n?'], input='y'
        )
        assert result.exit_code == 0, 'driver program failed'
        assert (
            result.stdout
            == """\
[1] baked beans
Will replace with spam. Confirm, y/n? y
Great!
"""
        ), 'driver program produced unexpected output'
        result = runner.invoke(
            driver,
            ['Will replace with spam, okay? ' '(Please say "y" or "n".)'],
            input='',
        )
        assert result.exit_code > 0, 'driver program succeeded?!'
        assert (
            result.stdout
            == """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".):\x20
Boo.
"""
        ), 'driver program produced unexpected output'
        assert isinstance(
            result.exception, IndexError
        ), 'driver program did not raise IndexError?!'

    def test_103_prompt_for_passphrase(self, monkeypatch: Any) -> None:
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
        monkeypatch: Any,
        command_line: list[str],
        config: dpp.types.VaultConfig,
        result_config: dpp.types.VaultConfig,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        for start_config in [config, result_config]:
            with tests.isolated_config(
                monkeypatch=monkeypatch, runner=runner, config=start_config
            ):
                result = runner.invoke(
                    cli.derivepassphrase, command_line, catch_exceptions=False
                )
                assert (result.exit_code, result.stderr_bytes) == (
                    0,
                    b'',
                ), 'program exited with failure'
                with open(cli._config_filename(), encoding='UTF-8') as infile:
                    config_readback = json.load(infile)
                assert config_readback == result_config

    def test_204_phrase_from_key_manually(self) -> None:
        assert (
            dpp.Vault(
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
        monkeypatch: Any,
        conn_hint: str,
    ) -> None:
        monkeypatch.setattr(
            ssh_agent_client.SSHAgentClient, 'list_keys', tests.list_keys
        )
        hint: ssh_agent_client.SSHAgentClient | socket.socket | None
        match conn_hint:
            case 'client':
                hint = ssh_agent_client.SSHAgentClient()
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
