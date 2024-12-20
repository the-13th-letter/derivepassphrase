# SPDX-FileCopyrightText: 2024 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import base64
import contextlib
import copy
import errno
import io
import json
import logging
import os
import shlex
import shutil
import socket
import textwrap
import warnings
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import stateful, strategies
from typing_extensions import Any, NamedTuple

import tests
from derivepassphrase import _types, cli, ssh_agent, vault

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator
    from typing import NoReturn

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

TEST_CONFIGS = tests.TEST_CONFIGS


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


def is_warning_line(line: str) -> bool:
    """Return true if the line is a warning line."""
    return ' Warning: ' in line or ' Deprecation warning: ' in line


def is_harmless_config_import_warning(record: tuple[str, int, str]) -> bool:
    """Return true if the warning is harmless, during config import."""
    possible_warnings = [
        'Replacing invalid value ',
        'Removing ineffective setting ',
        (
            'Setting a global passphrase is ineffective '
            'because a key is also set.'
        ),
        (
            'Setting a service passphrase is ineffective '
            'because a key is also set:'
        ),
    ]
    return any(tests.warning_emitted(w, [record]) for w in possible_warnings)


def vault_config_exporter_shell_interpreter(  # noqa: C901
    script: str | Iterable[str],
    /,
    *,
    prog_name_list: list[str] | None = None,
    command: click.BaseCommand | None = None,
    runner: click.testing.CliRunner | None = None,
) -> Iterator[click.testing.Result]:
    if isinstance(script, str):  # pragma: no cover
        script = script.splitlines(False)
    if prog_name_list is None:  # pragma: no cover
        prog_name_list = ['derivepassphrase', 'vault']
    if command is None:  # pragma: no cover
        command = cli.derivepassphrase_vault
    if runner is None:  # pragma: no cover
        runner = click.testing.CliRunner(mix_stderr=False)
    n = len(prog_name_list)
    it = iter(script)
    while True:
        try:
            raw_line = next(it)
        except StopIteration:
            break
        else:
            line = shlex.split(raw_line)
        input_buffer: list[str] = []
        if line[:n] != prog_name_list:
            continue
        line[:n] = []
        if line and line[-1] == '<<HERE':
            # naive HERE document support
            while True:
                try:
                    raw_line = next(it)
                except StopIteration as exc:  # pragma: no cover
                    msg = 'incomplete here document'
                    raise EOFError(msg) from exc
                else:
                    if raw_line == 'HERE':
                        break
                    input_buffer.append(raw_line)
            line.pop()
        yield runner.invoke(
            command,
            line,
            catch_exceptions=False,
            input=(''.join(x + '\n' for x in input_buffer) or None),
        )


class TestCLI:
    def test_200_help_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault, ['--help'], catch_exceptions=False
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
        charset = vault.Vault._CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                [option, '0', '-p', '--', DUMMY_SERVICE],
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
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--repeat', '0', '-p', '--', DUMMY_SERVICE],
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch, runner=runner, vault_config=config
        ):
            monkeypatch.setattr(
                vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            monkeypatch.setattr(
                vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['-k', '--', DUMMY_SERVICE],
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
        running_ssh_agent: tests.RunningSSHAgentInfo,
        config: dict[str, Any],
        key_index: int,
    ) -> None:
        with monkeypatch.context():
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            runner = click.testing.CliRunner(mix_stderr=False)
            with tests.isolated_vault_config(
                monkeypatch=monkeypatch, runner=runner, vault_config=config
            ):
                _result = runner.invoke(
                    cli.derivepassphrase_vault,
                    ['-k', '--', DUMMY_SERVICE],
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
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        with monkeypatch.context():
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            runner = click.testing.CliRunner(mix_stderr=False)
            with tests.isolated_vault_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config={
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
                    cli.derivepassphrase_vault,
                    ['--', DUMMY_SERVICE],
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

    @pytest.mark.parametrize(
        ['config', 'command_line'],
        [
            pytest.param(
                {
                    'global': {'key': DUMMY_KEY1_B64},
                    'services': {},
                },
                ['--config', '-p'],
                id='global',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {
                            'key': DUMMY_KEY1_B64,
                            **DUMMY_CONFIG_SETTINGS,
                        },
                    },
                },
                ['--config', '-p', '--', DUMMY_SERVICE],
                id='service',
            ),
            pytest.param(
                {
                    'global': {'key': DUMMY_KEY1_B64},
                    'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()},
                },
                ['--config', '-p', '--', DUMMY_SERVICE],
                id='service-over-global',
            ),
        ],
    )
    def test_206_setting_phrase_thus_overriding_key_in_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        command_line: list[str],
    ) -> None:
        with monkeypatch.context():
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            runner = click.testing.CliRunner(mix_stderr=False)
            with tests.isolated_vault_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=config,
            ):
                _result = runner.invoke(
                    cli.derivepassphrase_vault,
                    command_line,
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert not result.output.strip(), 'expected no program output'
        assert result.stderr, 'expected known error output'
        err_lines = result.stderr.splitlines(False)
        assert err_lines[0].startswith('Passphrase:')
        assert tests.warning_emitted(
            'Setting a service passphrase is ineffective ',
            caplog.record_tuples,
        ) or tests.warning_emitted(
            'Setting a global passphrase is ineffective ',
            caplog.record_tuples,
        ), 'expected known warning message'
        assert all(map(is_warning_line, result.stderr.splitlines(True)))
        assert all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'

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
        ):
            for value in '-42', 'invalid':
                _result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [option, value, '-p', '--', DUMMY_SERVICE],
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(_result)
                assert result.error_exit(
                    error='Invalid value'
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                options if service else [*options, '--', DUMMY_SERVICE],
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
            with tests.isolated_vault_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config={'global': {'phrase': 'abc'}, 'services': {}},
            ):
                monkeypatch.setattr(
                    cli, '_prompt_for_passphrase', tests.auto_prompt
                )
                _result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [*options, '--', DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    def test_211a_empty_service_name_causes_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        def is_expected_warning(record: tuple[str, int, str]) -> bool:
            return is_harmless_config_import_warning(
                record
            ) or tests.warning_emitted(
                'An empty SERVICE is not supported by vault(1)', [record]
            )

        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=30', '--', ''],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=False), 'expected clean exit'
            assert result.stderr is not None, 'expected known error output'
            assert all(
                map(is_expected_warning, caplog.record_tuples)
            ), 'expected known error output'
            assert cli._load_config() == {
                'global': {'length': 30},
                'services': {},
            }, 'requested configuration change was not applied'
            caplog.clear()
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps({'services': {'': {'length': 40}}}),
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=False), 'expected clean exit'
            assert result.stderr is not None, 'expected known error output'
            assert all(
                map(is_expected_warning, caplog.record_tuples)
            ), 'expected known error output'
            assert cli._load_config() == {
                'global': {'length': 30},
                'services': {'': {'length': 40}},
            }, 'requested configuration change was not applied'

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
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                [*options, '--', DUMMY_SERVICE] if service else options,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='mutually exclusive with '
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'config',
        [
            conf.config
            for conf in TEST_CONFIGS
            if tests.is_valid_test_config(conf)
        ],
    )
    def test_213_import_config_success(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config2 = json.load(infile)
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config2 == config, 'config not imported correctly'
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'

    @tests.hypothesis_settings_coverage_compatible_with_caplog
    @hypothesis.given(
        conf=tests.smudged_vault_test_config(
            strategies.sampled_from(TEST_CONFIGS).filter(
                tests.is_valid_test_config
            )
        )
    )
    def test_213a_import_config_success(
        self,
        caplog: pytest.LogCaptureFixture,
        conf: tests.VaultTestConfig,
    ) -> None:
        config = conf.config
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=pytest.MonkeyPatch(),
            runner=runner,
            vault_config={'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config3 = json.load(infile)
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config3 == config2, 'config not imported correctly'
        assert not result.stderr or all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'

    def test_213b_import_bad_config_not_vault_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Invalid vault config'
        ), 'expected error exit and known error message'

    def test_213c_import_bad_config_not_json_data(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='This string is not valid JSON.',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='cannot decode JSON'
        ), 'expected error exit and known error message'

    def test_213d_import_bad_config_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        # `isolated_vault_config` validates the configuration.  So, to
        # pass an actual broken configuration, we must open the
        # configuration file ourselves afterwards, inside the context.
        # We also might as well use `isolated_config` instead.
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            with open(
                cli._config_filename(subsystem='vault'), 'w', encoding='UTF-8'
            ) as outfile:
                print('This string is not valid JSON.', file=outfile)
            dname = cli._config_filename(subsystem=None)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', os.fsdecode(dname)],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=os.strerror(errno.EISDIR)
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214_export_settings_no_stored_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
        export_options: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename(subsystem='vault'))
            _result = runner.invoke(
                # Test parent context navigation by not calling
                # `cli.derivepassphrase_vault` directly.  Used e.g. in
                # the `--export-as=sh` section to autoconstruct the
                # program name correctly.
                cli.derivepassphrase,
                ['vault', '--export', '-', *export_options],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214a_export_settings_bad_stored_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        export_options: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch, runner=runner, vault_config={}
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214b_export_settings_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        export_options: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            with contextlib.suppress(FileNotFoundError):
                os.remove(cli._config_filename(subsystem='vault'))
            os.makedirs(cli._config_filename(subsystem='vault'))
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214c_export_settings_target_not_a_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        export_options: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            dname = cli._config_filename(subsystem=None)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', os.fsdecode(dname), *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot store config'
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214d_export_settings_settings_directory_not_a_directory(
        self,
        monkeypatch: pytest.MonkeyPatch,
        export_options: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree('.derivepassphrase')
            with open('.derivepassphrase', 'w', encoding='UTF-8') as outfile:
                print('Obstruction!!', file=outfile)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Cannot load config'
        ) or result.error_exit(
            error='Cannot load user config'
        ), 'expected error exit and known error message'

    def test_220_edit_notes_successfully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        edit_result = """

# - - - - - >8 - - - - - >8 - - - - - >8 - - - - - >8 - - - - -
contents go here
"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: edit_result)  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'contents go here'}},
            }

    def test_221_edit_notes_noop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: None)  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    def test_222_edit_notes_marker_removed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: 'long\ntext')  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'long\ntext'}},
            }

    def test_223_edit_notes_abort(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: '\n\n')  # noqa: ARG005
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='user aborted request'
            ), 'expected known error message'
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
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
                {
                    'global': {'key': DUMMY_KEY1_B64, 'phrase': 'abc'},
                    'services': {},
                },
            ),
            (
                ['--phrase', '--', 'sv'],
                'my passphrase\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'phrase': 'my passphrase'}},
                },
            ),
            (
                ['--key', '--', 'sv'],
                '1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64}},
                },
            ),
            (
                ['--key', '--length', '15', '--', 'sv'],
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.clean_exit(), 'expected clean exit'
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert (
                config == result_config
            ), 'stored config does not match expectation'

    @pytest.mark.parametrize(
        ['command_line', 'input', 'err_text'],
        [
            ([], '', 'Cannot update global settings without actual settings'),
            (
                ['--', 'sv'],
                '',
                'Cannot update service settings without actual settings',
            ),
            (['--phrase', '--', 'sv'], '', 'No passphrase given'),
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setattr(
                cli, '_get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            custom_error = 'custom error message'

            def raiser() -> None:
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_select_ssh_key', raiser)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
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
        skip_if_no_af_unix_support: None,
    ) -> None:
        del skip_if_no_af_unix_support
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setenv('SSH_AUTH_SOCK', os.getcwd())
            _result = runner.invoke(
                cli.derivepassphrase_vault,
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            tests.make_file_readonly(
                cli._config_filename(subsystem='vault'),
                try_race_free_implementation=try_race_free_implementation,
            )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
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
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            custom_error = 'custom error message'

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_save_config', raiser)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error=custom_error
        ), 'expected error exit and known error message'

    def test_225f_store_config_fail_unset_and_set_same_settings(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--unset=length',
                    '--length=15',
                    '--',
                    DUMMY_SERVICE,
                ],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='Attempted to unset and set --length at the same time.'
        ), 'expected error exit and known error message'

    def test_226_no_arguments(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault, [], catch_exceptions=False
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
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='No passphrase or key given'
        ), 'expected error exit and known error message'

    def test_230_config_directory_nonexistant(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """https://github.com/the-13th-letter/derivepassphrase/issues/6"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            shutil.rmtree('.derivepassphrase')
            os_makedirs_called = False
            real_os_makedirs = os.makedirs

            def makedirs(*args: Any, **kwargs: Any) -> Any:
                nonlocal os_makedirs_called
                os_makedirs_called = True
                return real_os_makedirs(*args, **kwargs)

            monkeypatch.setattr(os, 'makedirs', makedirs)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
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
            with open(
                cli._config_filename(subsystem='vault'), encoding='UTF-8'
            ) as infile:
                config_readback = json.load(infile)
            assert config_readback == {
                'global': {'phrase': 'abc'},
                'services': {},
            }, 'config mismatch'

    def test_230a_config_directory_not_a_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """https://github.com/the-13th-letter/derivepassphrase/issues/6"""
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
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
                cli.derivepassphrase_vault,
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
        ):
            custom_error = 'custom error message'

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli, '_save_config', raiser)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error=custom_error
            ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        ['main_config', 'command_line', 'input', 'warning_message'],
        [
            pytest.param(
                '',
                ['--import', '-'],
                json.dumps({
                    'global': {'phrase': 'Du\u0308sseldorf'},
                    'services': {},
                }),
                'the $.global passphrase is not NFC-normalized',
                id='global-NFC',
            ),
            pytest.param(
                '',
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'weird entry name': {'phrase': 'Du\u0308sseldorf'},
                    }
                }),
                (
                    'the $.services["weird entry name"] passphrase '
                    'is not NFC-normalized'
                ),
                id='service-weird-name-NFC',
            ),
            pytest.param(
                '',
                ['--config', '-p', '--', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                (
                    f'the $.services.{DUMMY_SERVICE} passphrase '
                    f'is not NFC-normalized'
                ),
                id='config-NFC',
            ),
            pytest.param(
                '',
                ['-p', '--', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                'the interactive input passphrase is not NFC-normalized',
                id='direct-input-NFC',
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'NFD'
                """),
                ['--import', '-'],
                json.dumps({
                    'global': {
                        'phrase': 'D\u00fcsseldorf',
                    },
                    'services': {},
                }),
                'the $.global passphrase is not NFD-normalized',
                id='global-NFD',
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'NFD'
                """),
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'weird entry name': {'phrase': 'D\u00fcsseldorf'},
                    },
                }),
                (
                    'the $.services["weird entry name"] passphrase '
                    'is not NFD-normalized'
                ),
                id='service-weird-name-NFD',
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault.unicode-normalization-form]
                'weird entry name 2' = 'NFKD'
                """),
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'weird entry name 1': {'phrase': 'D\u00fcsseldorf'},
                        'weird entry name 2': {'phrase': 'D\u00fcsseldorf'},
                    },
                }),
                (
                    'the $.services["weird entry name 2"] passphrase '
                    'is not NFKD-normalized'
                ),
                id='service-weird-name-2-NFKD',
            ),
        ],
    )
    def test_300_unicode_normalization_form_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        main_config: str,
        command_line: list[str],
        input: str | None,
        warning_message: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={
                'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}
            },
            main_config_str=main_config,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--debug', *command_line],
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.warning_emitted(
            warning_message, caplog.record_tuples
        ), 'expected known warning message in stderr'

    @pytest.mark.parametrize(
        ['main_config', 'command_line', 'input', 'error_message'],
        [
            pytest.param(
                textwrap.dedent(r"""
                [vault]
                default-unicode-normalization-form = 'XXX'
                """),
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'with_normalization': {'phrase': 'D\u00fcsseldorf'},
                    },
                }),
                (
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
                id='global',
            ),
            pytest.param(
                textwrap.dedent(r"""
                [vault.unicode-normalization-form]
                with_normalization = 'XXX'
                """),
                ['--import', '-'],
                json.dumps({
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'with_normalization': {'phrase': 'D\u00fcsseldorf'},
                    },
                }),
                (
                    "Invalid value 'XXX' for config key "
                    "vault.with_normalization.unicode-normalization-form"
                ),
                id='service',
            ),
        ],
    )
    def test_301_unicode_normalization_form_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        main_config: str,
        command_line: list[str],
        input: str | None,
        error_message: str,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={
                'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}
            },
            main_config_str=main_config,
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='The configuration file is invalid.'
        ), 'expected error exit and known error message'
        assert result.error_exit(
            error=error_message
        ), 'expected error exit and known error message'

    @pytest.mark.parametrize(
        'command_line',
        [
            pytest.param(
                ['--config', '--phrase'],
                id='configure global passphrase',
            ),
            pytest.param(
                ['--phrase', '--', DUMMY_SERVICE],
                id='interactive passphrase',
            ),
        ],
    )
    def test_301a_unicode_normalization_form_error_from_stored_config(
        self,
        monkeypatch: pytest.MonkeyPatch,
        command_line: list[str],
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={
                'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}
            },
            main_config_str=textwrap.dedent("""
            [vault]
            default-unicode-normalization-form = 'XXX'
            """),
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='The configuration file is invalid.'
            ), 'expected error exit and known error message'
            assert result.error_exit(
                error=(
                    "Invalid value 'XXX' for config key "
                    "vault.default-unicode-normalization-form"
                ),
            ), 'expected error exit and known error message'

    def test_310_bad_user_config_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'services': {}},
            main_config_str=textwrap.dedent("""
            This file is not valid TOML.
            """),
        ):
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--phrase', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
            assert result.error_exit(
                error='Cannot load user config:'
            ), 'expected error exit and known error message'

    def test_400_missing_af_unix_support(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config={'global': {'phrase': 'abc'}, 'services': {}},
        ):
            monkeypatch.setenv(
                'SSH_AUTH_SOCK', "the value doesn't even matter"
            )
            monkeypatch.delattr(socket, 'AF_UNIX', raising=False)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.error_exit(
            error='does not support UNIX domain sockets'
        ), 'expected error exit and known error message'


class TestCLIUtils:
    @pytest.mark.parametrize(
        'config',
        [
            {'global': {'phrase': 'my passphrase'}, 'services': {}},
            {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'phrase': 'my passphrase'}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
            },
        ],
    )
    def test_100_load_config(
        self, monkeypatch: pytest.MonkeyPatch, config: Any
    ) -> None:
        runner = click.testing.CliRunner()
        with tests.isolated_vault_config(
            monkeypatch=monkeypatch, runner=runner, vault_config=config
        ):
            config_filename = cli._config_filename(subsystem='vault')
            with open(config_filename, encoding='UTF-8') as fileobj:
                assert json.load(fileobj) == config
            assert cli._load_config() == config

    def test_110_save_bad_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner()
        # Use parenthesized context manager expressions here once Python
        # 3.9 becomes unsupported.
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch, runner=runner, vault_config={}
                )
            )
            stack.enter_context(
                pytest.raises(ValueError, match='Invalid vault config')
            )
            cli._save_config(None)  # type: ignore[arg-type]

    def test_111_prompt_for_selection_multiple(self) -> None:
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

    def test_112_prompt_for_selection_single(self) -> None:
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
            ['Will replace with spam, okay? (Please say "y" or "n".)'],
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

    def test_113_prompt_for_passphrase(
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

    def test_120_standard_logging_context_manager(
        self,
        caplog: pytest.LogCaptureFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        prog_name = cli.StandardCLILogging.prog_name
        package_name = cli.StandardCLILogging.package_name
        logger = logging.getLogger(package_name)
        deprecation_logger = logging.getLogger(f'{package_name}.deprecation')
        logging_cm = cli.StandardCLILogging.ensure_standard_logging()
        with logging_cm:
            assert (
                sum(
                    1
                    for h in logger.handlers
                    if h is cli.StandardCLILogging.cli_handler
                )
                == 1
            )
            logger.warning('message 1')
            with logging_cm:
                deprecation_logger.warning('message 2')
                assert (
                    sum(
                        1
                        for h in logger.handlers
                        if h is cli.StandardCLILogging.cli_handler
                    )
                    == 1
                )
                assert capsys.readouterr() == (
                    '',
                    (
                        f'{prog_name}: Warning: message 1\n'
                        f'{prog_name}: Deprecation warning: message 2\n'
                    ),
                )
            logger.warning('message 3')
            assert (
                sum(
                    1
                    for h in logger.handlers
                    if h is cli.StandardCLILogging.cli_handler
                )
                == 1
            )
            assert capsys.readouterr() == (
                '',
                f'{prog_name}: Warning: message 3\n',
            )
            assert caplog.record_tuples == [
                (package_name, logging.WARNING, 'message 1'),
                (f'{package_name}.deprecation', logging.WARNING, 'message 2'),
                (package_name, logging.WARNING, 'message 3'),
            ]

    def test_121_standard_logging_warnings_context_manager(
        self,
        caplog: pytest.LogCaptureFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        warnings_cm = cli.StandardCLILogging.ensure_standard_warnings_logging()
        THE_FUTURE = 'the future will be here sooner than you think'  # noqa: N806
        JUST_TESTING = 'just testing whether warnings work'  # noqa: N806
        with warnings_cm:
            assert (
                sum(
                    1
                    for h in logging.getLogger('py.warnings').handlers
                    if h is cli.StandardCLILogging.warnings_handler
                )
                == 1
            )
            warnings.warn(UserWarning(JUST_TESTING), stacklevel=1)
            with warnings_cm:
                warnings.warn(FutureWarning(THE_FUTURE), stacklevel=1)
                _out, err = capsys.readouterr()
                err_lines = err.splitlines(True)
                assert any(
                    f'UserWarning: {JUST_TESTING}' in line
                    for line in err_lines
                )
                assert any(
                    f'FutureWarning: {THE_FUTURE}' in line
                    for line in err_lines
                )
            warnings.warn(UserWarning(JUST_TESTING), stacklevel=1)
            _out, err = capsys.readouterr()
            err_lines = err.splitlines(True)
            assert any(
                f'UserWarning: {JUST_TESTING}' in line for line in err_lines
            )
            assert not any(
                f'FutureWarning: {THE_FUTURE}' in line for line in err_lines
            )
            record_tuples = caplog.record_tuples
            assert [tup[:2] for tup in record_tuples] == [
                ('py.warnings', logging.WARNING),
                ('py.warnings', logging.WARNING),
                ('py.warnings', logging.WARNING),
            ]
            assert f'UserWarning: {JUST_TESTING}' in record_tuples[0][2]
            assert f'FutureWarning: {THE_FUTURE}' in record_tuples[1][2]
            assert f'UserWarning: {JUST_TESTING}' in record_tuples[2][2]

    def _export_as_sh_helper(
        self,
        config: Any,
    ) -> None:
        prog_name_list = ('derivepassphrase', 'vault')
        with io.StringIO() as outfile:
            cli._print_config_as_sh_script(
                config, outfile=outfile, prog_name_list=prog_name_list
            )
            script = outfile.getvalue()
        runner = click.testing.CliRunner(mix_stderr=False)
        monkeypatch = pytest.MonkeyPatch()
        with tests.isolated_vault_config(
            runner=runner,
            monkeypatch=monkeypatch,
            vault_config={'services': {}},
        ):
            for _result in vault_config_exporter_shell_interpreter(script):
                result = tests.ReadableResult.parse(_result)
                assert result.clean_exit()
            assert cli._load_config() == config

    @hypothesis.given(
        global_config_settable=tests.vault_full_service_config(),
        global_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                'key': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                'phrase': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
            },
        ),
    )
    def test_130a_export_as_sh_global(
        self,
        global_config_settable: _types.VaultConfigServicesSettings,
        global_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        config: _types.VaultConfig = {
            'global': global_config_settable | global_config_importable,
            'services': {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self._export_as_sh_helper(config)

    @hypothesis.given(
        global_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                'key': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                'phrase': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
            },
        ),
    )
    def test_130b_export_as_sh_global_only_imports(
        self,
        global_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        config: _types.VaultConfig = {
            'global': global_config_importable,
            'services': {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        if not config['global']:
            config.pop('global')
        return self._export_as_sh_helper(config)

    @hypothesis.given(
        service_name=strategies.text(
            alphabet=strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
            ),
            min_size=4,
            max_size=64,
        ),
        service_config_settable=tests.vault_full_service_config(),
        service_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                'key': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                'phrase': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
                'notes': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                        include_characters=('\n', '\f', '\t'),
                    ),
                    max_size=256,
                ),
            },
        ),
    )
    def test_130c_export_as_sh_service(
        self,
        service_name: str,
        service_config_settable: _types.VaultConfigServicesSettings,
        service_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        config: _types.VaultConfig = {
            'services': {
                service_name: (
                    service_config_settable | service_config_importable
                ),
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self._export_as_sh_helper(config)

    @hypothesis.given(
        service_name=strategies.text(
            alphabet=strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
            ),
            min_size=4,
            max_size=64,
        ),
        service_config_importable=strategies.fixed_dictionaries(
            {},
            optional={
                'key': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=128,
                ),
                'phrase': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                    ),
                    max_size=64,
                ),
                'notes': strategies.text(
                    alphabet=strategies.characters(
                        min_codepoint=32,
                        max_codepoint=126,
                        include_characters=('\n', '\f', '\t'),
                    ),
                    max_size=256,
                ),
            },
        ),
    )
    def test_130d_export_as_sh_service_only_imports(
        self,
        service_name: str,
        service_config_importable: _types.VaultConfigServicesSettings,
    ) -> None:
        config: _types.VaultConfig = {
            'services': {
                service_name: service_config_importable,
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self._export_as_sh_helper(config)

    @pytest.mark.parametrize(
        ['command_line', 'config', 'result_config'],
        [
            (
                ['--delete-globals'],
                {'global': {'phrase': 'abc'}, 'services': {}},
                {'services': {}},
            ),
            (
                ['--delete', '--', DUMMY_SERVICE],
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
            with tests.isolated_vault_config(
                monkeypatch=monkeypatch,
                runner=runner,
                vault_config=start_config,
            ):
                _result = runner.invoke(
                    cli.derivepassphrase_vault,
                    command_line,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(_result)
                assert result.clean_exit(
                    empty_stderr=True
                ), 'expected clean exit'
                with open(
                    cli._config_filename(subsystem='vault'), encoding='UTF-8'
                ) as infile:
                    config_readback = json.load(infile)
                assert config_readback == result_config

    def test_204_phrase_from_key_manually(self) -> None:
        assert (
            vault.Vault(
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
        ctx = cli.derivepassphrase_vault.make_context(cli.PROG_NAME, [])
        param = cli.derivepassphrase_vault.params[0]
        assert vfunc(ctx, param, input) == input

    @pytest.mark.parametrize('conn_hint', ['none', 'socket', 'client'])
    def test_227_get_suitable_ssh_keys(
        self,
        monkeypatch: pytest.MonkeyPatch,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        conn_hint: str,
    ) -> None:
        with monkeypatch.context():
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            hint: ssh_agent.SSHAgentClient | socket.socket | None
            # Use match/case here once Python 3.9 becomes unsupported.
            if conn_hint == 'client':
                hint = ssh_agent.SSHAgentClient()
            elif conn_hint == 'socket':
                hint = socket.socket(family=socket.AF_UNIX)
                hint.connect(running_ssh_agent.socket)
            else:
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
                assert (
                    exception is None
                ), 'exception querying suitable SSH keys'

    def test_400_key_to_phrase(
        self,
        monkeypatch: pytest.MonkeyPatch,
        skip_if_no_af_unix_support: None,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
    ) -> None:

        class CustomError(RuntimeError):
            pass

        def err(*args: Any, **_kwargs: Any) -> NoReturn:
            args = args or ('custom error message',)
            raise CustomError(*args)

        def fail(*_args: Any, **_kwargs: Any) -> Any:
            raise ssh_agent.SSHAgentFailedError(
                _types.SSH_AGENT.FAILURE.value,
                b'',
            )

        del skip_if_no_af_unix_support
        monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', fail)
        loaded_keys = list(ssh_agent_client_with_test_keys_loaded.list_keys())
        loaded_key = base64.standard_b64encode(loaded_keys[0][0])
        with monkeypatch.context() as mp:
            mp.setattr(
                ssh_agent.SSHAgentClient,
                'list_keys',
                lambda *_a, **_kw: [],
            )
            with pytest.raises(CustomError, match='not loaded into the agent'):
                cli._key_to_phrase(loaded_key, error_callback=err)
        with monkeypatch.context() as mp:
            mp.setattr(ssh_agent.SSHAgentClient, 'list_keys', fail)
            with pytest.raises(
                CustomError, match='SSH agent failed to complete'
            ):
                cli._key_to_phrase(loaded_key, error_callback=err)
        with monkeypatch.context() as mp:
            mp.setattr(ssh_agent.SSHAgentClient, 'list_keys', err)
            with pytest.raises(
                CustomError, match='SSH agent failed to complete'
            ) as excinfo:
                cli._key_to_phrase(loaded_key, error_callback=err)
            assert excinfo.value.args
            assert isinstance(
                excinfo.value.args[0], ssh_agent.SSHAgentFailedError
            )
            assert excinfo.value.args[0].__context__ is not None
            assert isinstance(excinfo.value.args[0].__context__, CustomError)
        with monkeypatch.context() as mp:
            mp.delenv('SSH_AUTH_SOCK', raising=True)
            with pytest.raises(
                CustomError, match='Cannot find running SSH agent'
            ):
                cli._key_to_phrase(loaded_key, error_callback=err)
        with monkeypatch.context() as mp:
            mp.setenv(
                'SSH_AUTH_SOCK', os.environ['SSH_AUTH_SOCK'] + '~'
            )
            with pytest.raises(
                CustomError, match='Cannot connect to SSH agent'
            ):
                cli._key_to_phrase(loaded_key, error_callback=err)
        with monkeypatch.context() as mp:
            mp.delattr(socket, 'AF_UNIX', raising=True)
            with pytest.raises(
                CustomError, match='does not support UNIX domain sockets'
            ):
                cli._key_to_phrase(loaded_key, error_callback=err)


class TestCLITransition:
    def test_100_help_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase, ['--help'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True, output='currently implemented subcommands'
        ), 'expected clean exit, and known help text'

    def test_101_help_output_export(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['export', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True, output='only available subcommand'
        ), 'expected clean exit, and known help text'

    def test_102_help_output_export_vault(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['export', 'vault', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True, output='Read the vault-native configuration'
        ), 'expected clean exit, and known help text'

    def test_103_help_output_vault(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['vault', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(
            empty_stderr=True, output='Password generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use NUMBER=0, e.g. "--symbol 0"'
        ), 'expected clean exit, and option group epilog in help text'

    @pytest.mark.parametrize(
        'config',
        [
            {'global': {'phrase': 'my passphrase'}, 'services': {}},
            {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'phrase': 'my passphrase'}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
            },
        ],
    )
    def test_110_load_config_backup(
        self, monkeypatch: pytest.MonkeyPatch, config: Any
    ) -> None:
        runner = click.testing.CliRunner()
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            config_filename = cli._config_filename(
                subsystem='old settings.json'
            )
            with open(config_filename, 'w', encoding='UTF-8') as fileobj:
                print(json.dumps(config, indent=2), file=fileobj)
            assert cli._migrate_and_load_old_config()[0] == config

    @pytest.mark.parametrize(
        'config',
        [
            {'global': {'phrase': 'my passphrase'}, 'services': {}},
            {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'phrase': 'my passphrase'}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
            },
        ],
    )
    def test_111_migrate_config(
        self, monkeypatch: pytest.MonkeyPatch, config: Any
    ) -> None:
        runner = click.testing.CliRunner()
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            config_filename = cli._config_filename(
                subsystem='old settings.json'
            )
            with open(config_filename, 'w', encoding='UTF-8') as fileobj:
                print(json.dumps(config, indent=2), file=fileobj)
            assert cli._migrate_and_load_old_config() == (config, None)

    @pytest.mark.parametrize(
        'config',
        [
            {'global': {'phrase': 'my passphrase'}, 'services': {}},
            {'global': {'key': DUMMY_KEY1_B64}, 'services': {}},
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'phrase': 'my passphrase'}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64}},
            },
            {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
            },
        ],
    )
    def test_112_migrate_config_error(
        self, monkeypatch: pytest.MonkeyPatch, config: Any
    ) -> None:
        runner = click.testing.CliRunner()
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            config_filename = cli._config_filename(
                subsystem='old settings.json'
            )
            with open(config_filename, 'w', encoding='UTF-8') as fileobj:
                print(json.dumps(config, indent=2), file=fileobj)
            os.mkdir(cli._config_filename(subsystem='vault'))
            config2, err = cli._migrate_and_load_old_config()
            assert config2 == config
            assert isinstance(err, OSError)
            assert err.errno == errno.EISDIR

    @pytest.mark.parametrize(
        'config',
        [
            {'global': '', 'services': {}},
            {'global': 0, 'services': {}},
            {
                'global': {'phrase': 'abc'},
                'services': False,
            },
            {
                'global': {'phrase': 'abc'},
                'services': True,
            },
            {
                'global': {'phrase': 'abc'},
                'services': None,
            },
        ],
    )
    def test_113_migrate_config_error_bad_config_value(
        self, monkeypatch: pytest.MonkeyPatch, config: Any
    ) -> None:
        runner = click.testing.CliRunner()
        with tests.isolated_config(monkeypatch=monkeypatch, runner=runner):
            config_filename = cli._config_filename(
                subsystem='old settings.json'
            )
            with open(config_filename, 'w', encoding='UTF-8') as fileobj:
                print(json.dumps(config, indent=2), file=fileobj)
            with pytest.raises(ValueError, match=cli._INVALID_VAULT_CONFIG):
                cli._migrate_and_load_old_config()

    def test_200_forward_export_vault_path_parameter(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        pytest.importorskip('cryptography', minversion='38.0')
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_vault_exporter_config(
            monkeypatch=monkeypatch,
            runner=runner,
            vault_config=tests.VAULT_V03_CONFIG,
            vault_key=tests.VAULT_MASTER_KEY,
        ):
            monkeypatch.setenv('VAULT_KEY', tests.VAULT_MASTER_KEY)
            _result = runner.invoke(
                cli.derivepassphrase,
                ['export', 'VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required in v1.0', caplog.record_tuples
        )
        assert tests.warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert json.loads(result.output) == tests.VAULT_V03_CONFIG_DATA

    def test_201_forward_export_vault_empty_commandline(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        pytest.importorskip('cryptography', minversion='38.0')
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                ['export'],
            )
        result = tests.ReadableResult.parse(_result)
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required in v1.0', caplog.record_tuples
        )
        assert tests.warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(
            error="Missing argument 'PATH'"
        ), 'expected error exit and known error type'

    @pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    def test_210_forward_vault_disable_character_set(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        charset_name: str,
    ) -> None:
        monkeypatch.setattr(cli, '_prompt_for_passphrase', tests.auto_prompt)
        option = f'--{charset_name}'
        charset = vault.Vault._CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                [option, '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required in v1.0', caplog.record_tuples
        )
        assert tests.warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        for c in charset:
            assert (
                c not in result.output
            ), f'derived password contains forbidden character {c!r}'

    def test_211_forward_vault_empty_command_line(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            _result = runner.invoke(
                cli.derivepassphrase,
                [],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(_result)
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required in v1.0', caplog.record_tuples
        )
        assert tests.warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(
            error='SERVICE is required'
        ), 'expected error exit and known error type'

    def test_300_export_using_old_config_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        caplog.set_level(logging.INFO)
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            with open(
                cli._config_filename(subsystem='old settings.json'),
                'w',
                encoding='UTF-8',
            ) as fileobj:
                print(
                    json.dumps(
                        {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                        indent=2,
                    ),
                    file=fileobj,
                )
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'v0.1-style config file', caplog.record_tuples
        ), 'expected known warning message in stderr'
        assert tests.deprecation_info_emitted(
            'Successfully migrated to ', caplog.record_tuples
        ), 'expected known warning message in stderr'

    def test_300a_export_using_old_config_file_migration_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        runner = click.testing.CliRunner(mix_stderr=False)
        with tests.isolated_config(
            monkeypatch=monkeypatch,
            runner=runner,
        ):
            with open(
                cli._config_filename(subsystem='old settings.json'),
                'w',
                encoding='UTF-8',
            ) as fileobj:
                print(
                    json.dumps(
                        {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                        indent=2,
                    ),
                    file=fileobj,
                )

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise OSError(
                    errno.EACCES,
                    os.strerror(errno.EACCES),
                    cli._config_filename(subsystem='vault'),
                )

            monkeypatch.setattr(os, 'replace', raiser)
            _result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'v0.1-style config file', caplog.record_tuples
        ), 'expected known warning message in stderr'
        assert tests.warning_emitted(
            'Failed to migrate to ', caplog.record_tuples
        ), 'expected known warning message in stderr'


_known_services = (DUMMY_SERVICE, 'email', 'bank', 'work')
_valid_properties = (
    'length',
    'repeat',
    'upper',
    'lower',
    'number',
    'space',
    'dash',
    'symbol',
)


def _build_reduced_vault_config_settings(
    config: _types.VaultConfigServicesSettings,
    keys_to_purge: frozenset[str],
) -> _types.VaultConfigServicesSettings:
    config2 = copy.deepcopy(config)
    for key in keys_to_purge:
        config2.pop(key, None)  # type: ignore[misc]
    return config2


_services_strategy = strategies.builds(
    _build_reduced_vault_config_settings,
    tests.vault_full_service_config(),
    strategies.sets(
        strategies.sampled_from(_valid_properties),
        max_size=7,
    ),
)


def _assemble_config(
    global_data: _types.VaultConfigGlobalSettings,
    service_data: list[tuple[str, _types.VaultConfigServicesSettings]],
) -> _types.VaultConfig:
    services_dict = dict(service_data)
    return (
        {'global': global_data, 'services': services_dict}
        if global_data
        else {'services': services_dict}
    )


@strategies.composite
def _draw_service_name_and_data(
    draw: hypothesis.strategies.DrawFn,
    num_entries: int,
) -> tuple[tuple[str, _types.VaultConfigServicesSettings], ...]:
    possible_services = list(_known_services)
    selected_services: list[str] = []
    for _ in range(num_entries):
        selected_services.append(
            draw(strategies.sampled_from(possible_services))
        )
        possible_services.remove(selected_services[-1])
    return tuple(
        (service, draw(_services_strategy)) for service in selected_services
    )


_vault_full_config = strategies.builds(
    _assemble_config,
    _services_strategy,
    strategies.integers(
        min_value=2,
        max_value=4,
    ).flatmap(_draw_service_name_and_data),
)


@tests.hypothesis_settings_coverage_compatible
class ConfigManagementStateMachine(stateful.RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.runner = click.testing.CliRunner(mix_stderr=False)
        self.exit_stack = contextlib.ExitStack().__enter__()
        self.monkeypatch = self.exit_stack.enter_context(
            pytest.MonkeyPatch().context()
        )
        self.isolated_config = self.exit_stack.enter_context(
            tests.isolated_vault_config(
                monkeypatch=self.monkeypatch,
                runner=self.runner,
                vault_config={'services': {}},
            )
        )

    setting = stateful.Bundle('setting')
    configuration = stateful.Bundle('configuration')

    @stateful.initialize(
        target=configuration,
        configs=strategies.lists(
            _vault_full_config,
            min_size=8,
            max_size=8,
        ),
    )
    def declare_initial_configs(
        self,
        configs: Iterable[_types.VaultConfig],
    ) -> Iterable[_types.VaultConfig]:
        return stateful.multiple(*configs)

    @stateful.initialize(
        target=setting,
        configs=strategies.lists(
            _vault_full_config,
            min_size=4,
            max_size=4,
        )
    )
    def extract_initial_settings(
        self,
        configs: list[_types.VaultConfig],
    ) -> Iterable[_types.VaultConfigServicesSettings]:
        settings: list[_types.VaultConfigServicesSettings] = []
        for c in configs:
            settings.extend(c['services'].values())
        return stateful.multiple(*map(copy.deepcopy, settings))

    @staticmethod
    def fold_configs(
        c1: _types.VaultConfig, c2: _types.VaultConfig
    ) -> _types.VaultConfig:
        """Fold `c1` into `c2`, overriding the latter."""
        new_global_dict = c1.get('global', c2.get('global'))
        if new_global_dict is not None:
            return {
                'global': new_global_dict,
                'services': {**c2['services'], **c1['services']},
            }
        return {
            'services': {**c2['services'], **c1['services']},
        }

    @stateful.rule(
        target=configuration,
        config=configuration,
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(_valid_properties),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def set_globals(
        self,
        config: _types.VaultConfig,
        setting: _types.VaultConfigGlobalSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> _types.VaultConfig:
        cli._save_config(config)
        config_global = config.get('global', {})
        maybe_unset = set(maybe_unset) - setting.keys()
        if overwrite:
            config['global'] = config_global = {}
        elif maybe_unset:
            for key in maybe_unset:
                config_global.pop(key, None)  # type: ignore[misc]
        config.setdefault('global', {}).update(setting)
        assert _types.is_vault_config(config)
        # NOTE: This relies on settings_obj containing only the keys
        # "length", "repeat", "upper", "lower", "number", "space",
        # "dash" and "symbol".
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                '--config',
                '--overwrite-existing' if overwrite else '--merge-existing',
            ]
            + [f'--unset={key}' for key in maybe_unset]
            + [
                f'--{key}={value}'
                for key, value in setting.items()
                if key in _valid_properties
            ],
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False)
        assert cli._load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
        service=strategies.sampled_from(_known_services),
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(_valid_properties),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def set_service(
        self,
        config: _types.VaultConfig,
        service: str,
        setting: _types.VaultConfigServicesSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> _types.VaultConfig:
        cli._save_config(config)
        config_service = config['services'].get(service, {})
        maybe_unset = set(maybe_unset) - setting.keys()
        if overwrite:
            config['services'][service] = config_service = {}
        elif maybe_unset:
            for key in maybe_unset:
                config_service.pop(key, None)  # type: ignore[misc]
        config['services'].setdefault(service, {}).update(setting)
        assert _types.is_vault_config(config)
        # NOTE: This relies on settings_obj containing only the keys
        # "length", "repeat", "upper", "lower", "number", "space",
        # "dash" and "symbol".
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                '--config',
                '--overwrite-existing' if overwrite else '--merge-existing',
            ]
            + [f'--unset={key}' for key in maybe_unset]
            + [
                f'--{key}={value}'
                for key, value in setting.items()
                if key in _valid_properties
            ]
            + ['--', service],
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False)
        assert cli._load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_global(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        cli._save_config(config)
        config.pop('global', None)
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete-globals'],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False)
        assert cli._load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config_and_service=configuration.filter(
            lambda c: bool(c['services'])
        ).flatmap(
            lambda c: strategies.tuples(
                strategies.just(c),
                strategies.sampled_from(tuple(c['services'].keys())),
            )
        ),
    )
    def purge_service(
        self,
        config_and_service: tuple[_types.VaultConfig, str],
    ) -> _types.VaultConfig:
        config, service = config_and_service
        cli._save_config(config)
        config['services'].pop(service, None)
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete', '--', service],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False)
        assert cli._load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_all(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        cli._save_config(config)
        config = {'services': {}}
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--clear'],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(_result)
        assert result.clean_exit(empty_stderr=False)
        assert cli._load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        base_config=configuration,
        config_to_import=configuration,
        overwrite=strategies.booleans(),
    )
    def import_configuration(
        self,
        base_config: _types.VaultConfig,
        config_to_import: _types.VaultConfig,
        overwrite: bool,
    ) -> _types.VaultConfig:
        cli._save_config(base_config)
        config = (
            self.fold_configs(config_to_import, base_config)
            if not overwrite
            else config_to_import
        )
        assert _types.is_vault_config(config)
        _result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--import', '-']
            + (['--overwrite-existing'] if overwrite else []),
            input=json.dumps(config_to_import),
            catch_exceptions=False,
        )
        assert tests.ReadableResult.parse(_result).clean_exit(
            empty_stderr=False
        )
        assert cli._load_config() == config
        return config

    def teardown(self) -> None:
        self.exit_stack.close()


TestConfigManagement = ConfigManagementStateMachine.TestCase
