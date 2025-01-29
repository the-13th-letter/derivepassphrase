# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import copy
import errno
import io
import json
import logging
import os
import pathlib
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
from derivepassphrase._internals import cli_helpers, cli_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence
    from collections.abc import Set as AbstractSet
    from typing import NoReturn

    from typing_extensions import Literal

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


PASSPHRASE_GENERATION_OPTIONS: list[tuple[str, ...]] = [
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
    """A rudimentary sh(1) interpreter for `--export-as=sh` output.

    Assumes a script as emitted by `derivepassphrase vault
    --export-as=sh --export -` and interprets the calls to
    `derivepassphrase vault` within.  (One call per line, skips all
    other lines.)  Also has rudimentary support for (quoted)
    here-documents using `HERE` as the marker.

    """
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


class TestAllCLI:
    """Tests uniformly for all command-line interfaces."""

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    def test_100_help_output(self) -> None:
        """The top-level help text mentions subcommands.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase, ['--help'], catch_exceptions=False
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            empty_stderr=True, output='currently implemented subcommands'
        ), 'expected clean exit, and known help text'

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    def test_101_help_output_export(
        self,
    ) -> None:
        """The "export" subcommand help text mentions subcommands.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                ['export', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            empty_stderr=True, output='only available subcommand'
        ), 'expected clean exit, and known help text'

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    def test_102_help_output_export_vault(
        self,
    ) -> None:
        """The "export vault" subcommand help text has known content.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                ['export', 'vault', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            empty_stderr=True, output='Export a vault-native configuration'
        ), 'expected clean exit, and known help text'

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    def test_103_help_output_vault(
        self,
    ) -> None:
        """The "vault" subcommand help text has known content.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                ['vault', '--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            empty_stderr=True, output='Passphrase generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use $VISUAL or $EDITOR to configure'
        ), 'expected clean exit, and option group epilog in help text'

    @pytest.mark.parametrize(
        ['command', 'non_eager_arguments'],
        [
            pytest.param(
                [],
                [],
                id='top-nothing',
            ),
            pytest.param(
                [],
                ['export'],
                id='top-export',
            ),
            pytest.param(
                ['export'],
                [],
                id='export-nothing',
            ),
            pytest.param(
                ['export'],
                ['vault'],
                id='export-vault',
            ),
            pytest.param(
                ['export', 'vault'],
                [],
                id='export-vault-nothing',
            ),
            pytest.param(
                ['export', 'vault'],
                ['--format', 'this-format-doesnt-exist'],
                id='export-vault-args',
            ),
            pytest.param(
                ['vault'],
                [],
                id='vault-nothing',
            ),
            pytest.param(
                ['vault'],
                ['--export', './'],
                id='vault-args',
            ),
        ],
    )
    @pytest.mark.parametrize(
        'arguments',
        [['--help'], ['--version']],
        ids=['help', 'version'],
    )
    def test_200_eager_options(
        self,
        command: list[str],
        arguments: list[str],
        non_eager_arguments: list[str],
    ) -> None:
        """Eager options terminate option and argument processing."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                [*command, *arguments, *non_eager_arguments],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    @pytest.mark.parametrize(
        'no_color',
        [False, True],
        ids=['yescolor', 'nocolor'],
    )
    @pytest.mark.parametrize(
        'force_color',
        [False, True],
        ids=['noforce', 'force'],
    )
    @pytest.mark.parametrize(
        'isatty',
        [False, True],
        ids=['notty', 'tty'],
    )
    @pytest.mark.parametrize(
        ['command_line', 'input'],
        [
            (
                ['vault', '--import', '-'],
                '{"services": {"": {"length": 20}}}',
            ),
        ],
        ids=['cmd'],
    )
    def test_201_no_color_force_color(
        self,
        no_color: bool,
        force_color: bool,
        isatty: bool,
        command_line: list[str],
        input: str | None,
    ) -> None:
        """Respect the `NO_COLOR` and `FORCE_COLOR` environment variables."""
        # Force color on if force_color.  Otherwise force color off if
        # no_color.  Otherwise set color if and only if we have a TTY.
        color = force_color or not no_color if isatty else force_color
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            if no_color:
                monkeypatch.setenv('NO_COLOR', 'yes')
            if force_color:
                monkeypatch.setenv('FORCE_COLOR', 'yes')
            result_ = runner.invoke(
                cli.derivepassphrase,
                command_line,
                input=input,
                catch_exceptions=False,
                color=isatty,
            )
            result = tests.ReadableResult.parse(result_)
        assert (
            not color
            or '\x1b[0m' in result.stderr
            or '\x1b[m' in result.stderr
        ), 'Expected color, but found no ANSI reset sequence'
        assert color or '\x1b[' not in result.stderr, (
            'Expected no color, but found an ANSI control sequence'
        )


class TestCLI:
    """Tests for the `derivepassphrase vault` command-line interface."""

    def test_200_help_output(
        self,
    ) -> None:
        """The `--help` option emits help text."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--help'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            empty_stderr=True, output='Passphrase generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use $VISUAL or $EDITOR to configure'
        ), 'expected clean exit, and option group epilog in help text'

    def test_200a_version_output(
        self,
    ) -> None:
        """The `--version` option emits version information."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--version'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True, output=cli.PROG_NAME), (
            'expected clean exit, and program name in version text'
        )
        assert result.clean_exit(empty_stderr=True, output=cli.__version__), (
            'expected clean exit, and version in help text'
        )

    @pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    def test_201_disable_character_set(
        self,
        charset_name: str,
    ) -> None:
        """Named character classes can be disabled on the command-line."""
        option = f'--{charset_name}'
        charset = vault.Vault.CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                [option, '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), 'expected clean exit:'
        for c in charset:
            assert c not in result.output, (
                f'derived password contains forbidden character {c!r}'
            )

    def test_202_disable_repetition(
        self,
    ) -> None:
        """Character repetition can be disabled on the command-line."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--repeat', '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), (
            'expected clean exit and empty stderr'
        )
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
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured SSH key will be used."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            monkeypatch.setattr(
                vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=True), (
            'expected clean exit and empty stderr'
        )
        assert result_.stdout_bytes
        assert result_.stdout_bytes.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE, (
            'known false output: phrase-based instead of key-based'
        )
        assert result_.stdout_bytes.rstrip(b'\n') == DUMMY_RESULT_KEY1, (
            'expected known output'
        )

    def test_204b_key_from_command_line(
        self,
    ) -> None:
        """An SSH key requested on the command-line will be used."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            monkeypatch.setattr(
                vault.Vault, 'phrase_from_key', tests.phrase_from_key
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['-k', '--', DUMMY_SERVICE],
                input='1\n',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert result_.stdout_bytes, 'expected program output'
        last_line = result_.stdout_bytes.splitlines(True)[-1]
        assert last_line.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE, (
            'known false output: phrase-based instead of key-based'
        )
        assert last_line.rstrip(b'\n') == DUMMY_RESULT_KEY1, (
            'expected known output'
        )

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
        running_ssh_agent: tests.RunningSSHAgentInfo,
        config: dict[str, Any],
        key_index: int,
    ) -> None:
        """A command-line SSH key will override the configured key."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['-k', '--', DUMMY_SERVICE],
                input=f'{key_index}\n',
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert result.output, 'expected program output'
        assert result.stderr, 'expected stderr'
        assert 'Error:' not in result.stderr, (
            'expected no error messages on stderr'
        )

    def test_205_service_phrase_if_key_in_global_config(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """A command-line passphrase will override the configured key."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
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
                )
            )
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert result_.stdout_bytes, 'expected program output'
        last_line = result_.stdout_bytes.splitlines(True)[-1]
        assert last_line.rstrip(b'\n') != DUMMY_RESULT_PASSPHRASE, (
            'known false output: phrase-based instead of key-based'
        )
        assert last_line.rstrip(b'\n') == DUMMY_RESULT_KEY1, (
            'expected known output'
        )

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
        running_ssh_agent: tests.RunningSSHAgentInfo,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        command_line: list[str],
    ) -> None:
        """Configuring a passphrase atop an SSH key works, but warns."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', tests.sign)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
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
        self,
        option: str,
    ) -> None:
        """Requesting invalidly many characters from a class fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            for value in '-42', 'invalid':
                result_ = runner.invoke(
                    cli.derivepassphrase_vault,
                    [option, value, '-p', '--', DUMMY_SERVICE],
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(result_)
                assert result.error_exit(error='Invalid value'), (
                    'expected error exit and known error message'
                )

    @pytest.mark.parametrize(
        ['options', 'service', 'input', 'check_success'],
        [
            pytest.param(
                o.options,
                o.needs_service,
                o.input,
                o.check_success,
                id=' '.join(o.options),
            )
            for o in INTERESTING_OPTION_COMBINATIONS
            if not o.incompatible
        ],
    )
    def test_211_service_needed(
        self,
        options: list[str],
        service: bool | None,
        input: str | None,
        check_success: bool,
    ) -> None:
        """We require or forbid a service argument, depending on options."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                options if service else [*options, '--', DUMMY_SERVICE],
                input=input,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            if service is not None:
                err_msg = (
                    ' requires a SERVICE'
                    if service
                    else ' does not take a SERVICE argument'
                )
                assert result.error_exit(error=err_msg), (
                    'expected error exit and known error message'
                )
            else:
                assert result.clean_exit(empty_stderr=True), (
                    'expected clean exit'
                )
        if check_success:
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with contextlib.ExitStack() as stack:
                monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
                stack.enter_context(
                    tests.isolated_vault_config(
                        monkeypatch=monkeypatch,
                        runner=runner,
                        vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                    )
                )
                monkeypatch.setattr(
                    cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
                )
                result_ = runner.invoke(
                    cli.derivepassphrase_vault,
                    [*options, '--', DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    def test_211a_empty_service_name_causes_warning(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Using an empty service name (where permissible) warns.

        Only the `--config` option can optionally take a service name.

        """

        def is_expected_warning(record: tuple[str, int, str]) -> bool:
            return is_harmless_config_import_warning(
                record
            ) or tests.warning_emitted(
                'An empty SERVICE is not supported by vault(1)', [record]
            )

        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=30', '--', ''],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=False), 'expected clean exit'
            assert result.stderr is not None, 'expected known error output'
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                'expected known error output'
            )
            assert cli_helpers.load_config() == {
                'global': {'length': 30},
                'services': {},
            }, 'requested configuration change was not applied'
            caplog.clear()
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps({'services': {'': {'length': 40}}}),
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=False), 'expected clean exit'
            assert result.stderr is not None, 'expected known error output'
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                'expected known error output'
            )
            assert cli_helpers.load_config() == {
                'global': {'length': 30},
                'services': {'': {'length': 40}},
            }, 'requested configuration change was not applied'

    @pytest.mark.parametrize(
        ['options', 'service'],
        [
            pytest.param(o.options, o.needs_service, id=' '.join(o.options))
            for o in INTERESTING_OPTION_COMBINATIONS
            if o.incompatible
        ],
    )
    def test_212_incompatible_options(
        self,
        options: list[str],
        service: bool | None,
    ) -> None:
        """Incompatible options are detected."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                [*options, '--', DUMMY_SERVICE] if service else options,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='mutually exclusive with '), (
            'expected error exit and known error message'
        )

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
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Importing a configuration works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config2 = json.load(infile)
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config2 == config, 'config not imported correctly'
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'

    @tests.hypothesis_settings_coverage_compatible_with_caplog
    @hypothesis.given(
        conf=tests.smudged_vault_test_config(
            strategies.sampled_from([
                conf
                for conf in tests.TEST_CONFIGS
                if tests.is_valid_test_config(conf)
            ])
        )
    )
    def test_213a_import_config_success(
        self,
        caplog: pytest.LogCaptureFixture,
        conf: tests.VaultTestConfig,
    ) -> None:
        """Importing a smudged configuration works.

        Tested via hypothesis.

        """
        config = conf.config
        config2 = copy.deepcopy(config)
        _types.clean_up_falsy_vault_config_values(config2)
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config3 = json.load(infile)
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config3 == config2, 'config not imported correctly'
        assert not result.stderr or all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'

    def test_213b_import_bad_config_not_vault_config(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Invalid vault config'), (
            'expected error exit and known error message'
        )

    def test_213c_import_bad_config_not_json_data(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='This string is not valid JSON.',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='cannot decode JSON'), (
            'expected error exit and known error message'
        )

    def test_213d_import_bad_config_not_a_file(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # `isolated_vault_config` ensures the configuration is valid
        # JSON.  So, to pass an actual broken configuration, we must
        # open the configuration file ourselves afterwards, inside the
        # context.
        #
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            cli_helpers.config_filename(subsystem='vault').write_text(
                'This string is not valid JSON.\n', encoding='UTF-8'
            )
            dname = cli_helpers.config_filename(subsystem=None)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', os.fsdecode(dname)],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=os.strerror(errno.EISDIR)), (
            'expected error exit and known error message'
        )

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214_export_settings_no_stored_settings(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting the default, empty config works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='vault').unlink(missing_ok=True)
            result_ = runner.invoke(
                # Test parent context navigation by not calling
                # `cli.derivepassphrase_vault` directly.  Used e.g. in
                # the `--export-as=sh` section to autoconstruct the
                # program name correctly.
                cli.derivepassphrase,
                ['vault', '--export', '-', *export_options],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
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
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={},
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot load vault settings:'), (
            'expected error exit and known error message'
        )

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214b_export_settings_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            config_file = cli_helpers.config_filename(subsystem='vault')
            config_file.unlink(missing_ok=True)
            config_file.mkdir(parents=True, exist_ok=True)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot load vault settings:'), (
            'expected error exit and known error message'
        )

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214c_export_settings_target_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            dname = cli_helpers.config_filename(subsystem=None)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', os.fsdecode(dname), *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot export vault settings:'), (
            'expected error exit and known error message'
        )

    @pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    def test_214d_export_settings_settings_directory_not_a_directory(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            config_dir = cli_helpers.config_filename(subsystem=None)
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(config_dir)
            config_dir.write_text('Obstruction!!\n')
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='Cannot load vault settings:'
        ) or result.error_exit(error='Cannot load user config:'), (
            'expected error exit and known error message'
        )

    def test_220_edit_notes_successfully(
        self,
    ) -> None:
        """Editing notes works."""
        edit_result = """

# - - - - - >8 - - - - - >8 - - - - - >8 - - - - - >8 - - - - -
contents go here
"""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: edit_result)  # noqa: ARG005
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'contents go here'}},
            }

    def test_221_edit_notes_noop(
        self,
    ) -> None:
        """Abandoning edited notes works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: None)  # noqa: ARG005
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    # TODO(the-13th-letter): Keep this behavior or not, with or without
    # warning?
    def test_222_edit_notes_marker_removed(
        self,
    ) -> None:
        """Removing the notes marker still saves the notes.

        TODO: Keep this behavior or not, with or without warning?

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: 'long\ntext')  # noqa: ARG005
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(empty_stderr=True), 'expected clean exit'
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': 'long\ntext'}},
            }

    def test_223_edit_notes_abort(
        self,
    ) -> None:
        """Aborting editing notes works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *a, **kw: '\n\n')  # noqa: ARG005
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--notes', '--', 'sv'],
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.error_exit(error='the user aborted the request'), (
                'expected known error message'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {'global': {'phrase': 'abc'}, 'services': {}}

    @pytest.mark.parametrize(
        ['command_line', 'input', 'result_config'],
        [
            pytest.param(
                ['--phrase'],
                'my passphrase\n',
                {'global': {'phrase': 'my passphrase'}, 'services': {}},
                id='phrase',
            ),
            pytest.param(
                ['--key'],
                '1\n',
                {
                    'global': {'key': DUMMY_KEY1_B64, 'phrase': 'abc'},
                    'services': {},
                },
                id='key',
            ),
            pytest.param(
                ['--phrase', '--', 'sv'],
                'my passphrase\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'phrase': 'my passphrase'}},
                },
                id='phrase-sv',
            ),
            pytest.param(
                ['--key', '--', 'sv'],
                '1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64}},
                },
                id='key-sv',
            ),
            pytest.param(
                ['--key', '--length', '15', '--', 'sv'],
                '1\n',
                {
                    'global': {'phrase': 'abc'},
                    'services': {'sv': {'key': DUMMY_KEY1_B64, 'length': 15}},
                },
                id='key-length-sv',
            ),
        ],
    )
    def test_224_store_config_good(
        self,
        command_line: list[str],
        input: str,
        result_config: Any,
    ) -> None:
        """Storing valid settings via `--config` works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(), 'expected clean exit'
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == result_config, (
                'stored config does not match expectation'
            )

    @pytest.mark.parametrize(
        ['command_line', 'input', 'err_text'],
        [
            pytest.param(
                [],
                '',
                'Cannot update the global settings without any given settings',
                id='None',
            ),
            pytest.param(
                ['--', 'sv'],
                '',
                'Cannot update the service-specific settings without any given settings',
                id='None-sv',
            ),
            pytest.param(
                ['--phrase', '--', 'sv'],
                '',
                'No passphrase was given',
                id='phrase-sv',
            ),
            pytest.param(
                ['--key'],
                '',
                'No SSH key was selected',
                id='key-sv',
            ),
        ],
    )
    def test_225_store_config_fail(
        self,
        command_line: list[str],
        input: str,
        err_text: str,
    ) -> None:
        """Storing invalid settings via `--config` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'get_suitable_ssh_keys', tests.suitable_ssh_keys
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=err_text), (
            'expected error exit and known error message'
        )

    def test_225a_store_config_fail_manual_no_ssh_key_selection(
        self,
    ) -> None:
        """Not selecting an SSH key during `--config --key` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            custom_error = 'custom error message'

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli_helpers, 'select_ssh_key', raiser)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=custom_error), (
            'expected error exit and known error message'
        )

    def test_225b_store_config_fail_manual_no_ssh_agent(
        self,
        skip_if_no_af_unix_support: None,
    ) -> None:
        """Not running an SSH agent during `--config --key` fails."""
        del skip_if_no_af_unix_support
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.delenv('SSH_AUTH_SOCK', raising=False)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot find any running SSH agent'), (
            'expected error exit and known error message'
        )

    def test_225c_store_config_fail_manual_bad_ssh_agent_connection(
        self,
    ) -> None:
        """Not running a reachable SSH agent during `--config --key` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            cwd = pathlib.Path.cwd().resolve()
            monkeypatch.setenv('SSH_AUTH_SOCK', str(cwd))
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot connect to the SSH agent'), (
            'expected error exit and known error message'
        )

    @pytest.mark.parametrize('try_race_free_implementation', [True, False])
    def test_225d_store_config_fail_manual_read_only_file(
        self,
        try_race_free_implementation: bool,
    ) -> None:
        """Using a read-only configuration file with `--config` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            tests.make_file_readonly(
                cli_helpers.config_filename(subsystem='vault'),
                try_race_free_implementation=try_race_free_implementation,
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='Cannot store vault settings:'), (
            'expected error exit and known error message'
        )

    def test_225e_store_config_fail_manual_custom_error(
        self,
    ) -> None:
        """OS-erroring with `--config` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            custom_error = 'custom error message'

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli_helpers, 'save_config', raiser)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=custom_error), (
            'expected error exit and known error message'
        )

    def test_225f_store_config_fail_unset_and_set_same_settings(
        self,
    ) -> None:
        """Issuing conflicting settings to `--config` fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            result_ = runner.invoke(
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
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='Attempted to unset and set --length at the same time.'
        ), 'expected error exit and known error message'

    def test_225g_store_config_fail_manual_ssh_agent_no_keys_loaded(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """Not holding any SSH keys during `--config --key` fails."""
        del running_ssh_agent
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )

            def func(
                *_args: Any,
                **_kwargs: Any,
            ) -> list[_types.SSHKeyCommentPair]:
                return []

            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'list_keys', func)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='no keys suitable'), (
            'expected error exit and known error message'
        )

    def test_225h_store_config_fail_manual_ssh_agent_runtime_error(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """The SSH agent erroring during `--config --key` fails."""
        del running_ssh_agent
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise ssh_agent.TrailingDataError()

            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'list_keys', raiser)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='violates the communications protocol.'
        ), 'expected error exit and known error message'

    def test_225i_store_config_fail_manual_ssh_agent_refuses(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """The SSH agent refusing during `--config --key` fails."""
        del running_ssh_agent
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )

            def func(*_args: Any, **_kwargs: Any) -> NoReturn:
                raise ssh_agent.SSHAgentFailedError(
                    _types.SSH_AGENT.FAILURE, b''
                )

            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'list_keys', func)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='refused to'), (
            'expected error exit and known error message'
        )

    def test_226_no_arguments(self) -> None:
        """Calling `derivepassphrase vault` without any arguments fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault, [], catch_exceptions=False
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='Deriving a passphrase requires a SERVICE'
        ), 'expected error exit and known error message'

    def test_226a_no_passphrase_or_key(
        self,
    ) -> None:
        """Deriving a passphrase without a passphrase or key fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error='No passphrase or key was given'), (
            'expected error exit and known error message'
        )

    def test_230_config_directory_nonexistant(
        self,
    ) -> None:
        """Running without an existing config directory works.

        This is a regression test; see [issue\u00a0#6][] for context.

        [issue #6]: https://github.com/the-13th-letter/derivepassphrase/issues/6

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(cli_helpers.config_filename(subsystem=None))
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(), 'expected clean exit'
            assert result.stderr == 'Passphrase:', (
                'program unexpectedly failed?!'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config_readback = json.load(infile)
            assert config_readback == {
                'global': {'phrase': 'abc'},
                'services': {},
            }, 'config mismatch'

    def test_230a_config_directory_not_a_file(
        self,
    ) -> None:
        """Erroring without an existing config directory errors normally.

        That is, the missing configuration directory does not cause any
        errors by itself.

        This is a regression test; see [issue\u00a0#6][] for context.

        [issue #6]: https://github.com/the-13th-letter/derivepassphrase/issues/6

        """
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            save_config_ = cli_helpers.save_config

            def obstruct_config_saving(*args: Any, **kwargs: Any) -> Any:
                config_dir = cli_helpers.config_filename(subsystem=None)
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(config_dir)
                config_dir.write_text('Obstruction!!\n')
                monkeypatch.setattr(cli_helpers, 'save_config', save_config_)
                return save_config_(*args, **kwargs)

            monkeypatch.setattr(cli_helpers, 'save_config', obstruct_config_saving)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(result_)
            assert result.error_exit(error='Cannot store vault settings:'), (
                'expected error exit and known error message'
            )

    def test_230b_store_config_custom_error(
        self,
    ) -> None:
        """Storing the configuration reacts even to weird errors."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            custom_error = 'custom error message'

            def raiser(config: Any) -> None:
                del config
                raise RuntimeError(custom_error)

            monkeypatch.setattr(cli_helpers, 'save_config', raiser)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            result = tests.ReadableResult.parse(result_)
            assert result.error_exit(error=custom_error), (
                'expected error exit and known error message'
            )

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
                'The $.global passphrase is not NFC-normalized',
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
                    'The $.services["weird entry name"] passphrase '
                    'is not NFC-normalized'
                ),
                id='service-weird-name-NFC',
            ),
            pytest.param(
                '',
                ['--config', '-p', '--', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                (
                    f'The $.services.{DUMMY_SERVICE} passphrase '
                    f'is not NFC-normalized'
                ),
                id='config-NFC',
            ),
            pytest.param(
                '',
                ['-p', '--', DUMMY_SERVICE],
                'Du\u0308sseldorf',
                'The interactive input passphrase is not NFC-normalized',
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
                'The $.global passphrase is not NFD-normalized',
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
                    'The $.services["weird entry name"] passphrase '
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
                    'The $.services["weird entry name 2"] passphrase '
                    'is not NFKD-normalized'
                ),
                id='service-weird-name-2-NFKD',
            ),
        ],
    )
    def test_300_unicode_normalization_form_warning(
        self,
        caplog: pytest.LogCaptureFixture,
        main_config: str,
        command_line: list[str],
        input: str | None,
        warning_message: str,
    ) -> None:
        """Using unnormalized Unicode passphrases warns."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=main_config,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--debug', *command_line],
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.warning_emitted(warning_message, caplog.record_tuples), (
            'expected known warning message in stderr'
        )

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
                    'vault.default-unicode-normalization-form'
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
                    'vault.with_normalization.unicode-normalization-form'
                ),
                id='service',
            ),
        ],
    )
    def test_301_unicode_normalization_form_error(
        self,
        main_config: str,
        command_line: list[str],
        input: str | None,
        error_message: str,
    ) -> None:
        """Using unknown Unicode normalization forms fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=main_config,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                catch_exceptions=False,
                input=input,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='The user configuration file is invalid.'
        ), 'expected error exit and known error message'
        assert result.error_exit(error=error_message), (
            'expected error exit and known error message'
        )

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
        command_line: list[str],
    ) -> None:
        """Using unknown Unicode normalization forms in the config fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {
                            DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()
                        }
                    },
                    main_config_str=(
                        "[vault]\ndefault-unicode-normalization-form = 'XXX'\n"
                    ),
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.error_exit(
                error='The user configuration file is invalid.'
            ), 'expected error exit and known error message'
            assert result.error_exit(
                error=(
                    "Invalid value 'XXX' for config key "
                    'vault.default-unicode-normalization-form'
                ),
            ), 'expected error exit and known error message'

    def test_310_bad_user_config_file(
        self,
    ) -> None:
        """Loading a user configuration file in an invalid format fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                    main_config_str='This file is not valid TOML.\n',
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--phrase', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
            assert result.error_exit(error='Cannot load user config:'), (
                'expected error exit and known error message'
            )

    def test_400_missing_af_unix_support(
        self,
    ) -> None:
        """Querying the SSH agent without `AF_UNIX` support fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'global': {'phrase': 'abc'}, 'services': {}},
                )
            )
            monkeypatch.setenv(
                'SSH_AUTH_SOCK', "the value doesn't even matter"
            )
            monkeypatch.delattr(socket, 'AF_UNIX', raising=False)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(
            error='does not support UNIX domain sockets'
        ), 'expected error exit and known error message'


class TestCLIUtils:
    """Tests for command-line utility functions."""

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
        self,
        config: Any,
    ) -> None:
        """[`cli_helpers.load_config`][] works for valid configurations."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            config_filename = cli_helpers.config_filename(subsystem='vault')
            with config_filename.open(encoding='UTF-8') as fileobj:
                assert json.load(fileobj) == config
            assert cli_helpers.load_config() == config

    def test_110_save_bad_config(
        self,
    ) -> None:
        """[`cli_helpers.save_config`][] fails for bad configurations."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={},
                )
            )
            stack.enter_context(
                pytest.raises(ValueError, match='Invalid vault config')
            )
            cli_helpers.save_config(None)  # type: ignore[arg-type]

    def test_111_prompt_for_selection_multiple(self) -> None:
        """[`cli_helpers.prompt_for_selection`][] works in the "multiple" case."""

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
            index = cli_helpers.prompt_for_selection(items, heading=heading)
            click.echo('A fine choice: ', nl=False)
            click.echo(items[index])
            click.echo('(Note: Vikings strictly optional.)')

        runner = click.testing.CliRunner(mix_stderr=True)
        result_ = runner.invoke(driver, [], input='9')
        result = tests.ReadableResult.parse(result_)
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
"""
        ), 'expected clean exit'
        result_ = runner.invoke(
            driver, ['--heading='], input='', catch_exceptions=True
        )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=IndexError), (
            'expected error exit and known error type'
        )
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
"""
        ), 'expected known output'

    def test_112_prompt_for_selection_single(self) -> None:
        """[`cli_helpers.prompt_for_selection`][] works in the "single" case."""

        @click.command()
        @click.option('--item', default='baked beans')
        @click.argument('prompt')
        def driver(item: str, prompt: str) -> None:
            try:
                cli_helpers.prompt_for_selection(
                    [item], heading='', single_choice_prompt=prompt
                )
            except IndexError:
                click.echo('Boo.')
                raise
            else:
                click.echo('Great!')

        runner = click.testing.CliRunner(mix_stderr=True)
        result_ = runner.invoke(
            driver, ['Will replace with spam. Confirm, y/n?'], input='y'
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(
            output="""\
[1] baked beans
Will replace with spam. Confirm, y/n? y
Great!
"""
        ), 'expected clean exit'
        result_ = runner.invoke(
            driver,
            ['Will replace with spam, okay? (Please say "y" or "n".)'],
            input='',
        )
        result = tests.ReadableResult.parse(result_)
        assert result.error_exit(error=IndexError), (
            'expected error exit and known error type'
        )
        assert (
            result.output
            == """\
[1] baked beans
Will replace with spam, okay? (Please say "y" or "n".):\x20
Boo.
"""
        ), 'expected known output'

    def test_113_prompt_for_passphrase(
        self,
    ) -> None:
        """[`cli_helpers.prompt_for_passphrase`][] works."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                click,
                'prompt',
                lambda *a, **kw: json.dumps({'args': a, 'kwargs': kw}),
            )
            res = json.loads(cli_helpers.prompt_for_passphrase())
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
        """The standard logging context manager works.

        It registers its handlers, once, and emits formatted calls to
        standard error prefixed with the program name.

        """
        prog_name = cli_machinery.StandardCLILogging.prog_name
        package_name = cli_machinery.StandardCLILogging.package_name
        logger = logging.getLogger(package_name)
        deprecation_logger = logging.getLogger(f'{package_name}.deprecation')
        logging_cm = cli_machinery.StandardCLILogging.ensure_standard_logging()
        with logging_cm:
            assert (
                sum(
                    1
                    for h in logger.handlers
                    if h is cli_machinery.StandardCLILogging.cli_handler
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
                        if h is cli_machinery.StandardCLILogging.cli_handler
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
                    if h is cli_machinery.StandardCLILogging.cli_handler
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
        """The standard warnings logging context manager works.

        It registers its handlers, once, and emits formatted calls to
        standard error prefixed with the program name.  It also adheres
        to the global warnings filter concerning which messages it
        actually emits to standard error.

        """
        warnings_cm = cli_machinery.StandardCLILogging.ensure_standard_warnings_logging()
        THE_FUTURE = 'the future will be here sooner than you think'  # noqa: N806
        JUST_TESTING = 'just testing whether warnings work'  # noqa: N806
        with warnings_cm:
            assert (
                sum(
                    1
                    for h in logging.getLogger('py.warnings').handlers
                    if h is cli_machinery.StandardCLILogging.warnings_handler
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

    def export_as_sh_helper(
        self,
        config: Any,
    ) -> None:
        """Emits a config in sh(1) format, then reads it back to verify it.

        This function exports the configuration, sets up a new
        enviroment, then calls
        [`vault_config_exporter_shell_interpreter`][] on the export
        script, verifying that each command ran successfully and that
        the final configuration matches the initial one.

        Args:
            config:
                The configuration to emit and read back.

        """
        prog_name_list = ('derivepassphrase', 'vault')
        with io.StringIO() as outfile:
            cli_helpers.print_config_as_sh_script(
                config, outfile=outfile, prog_name_list=prog_name_list
            )
            script = outfile.getvalue()
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            for result_ in vault_config_exporter_shell_interpreter(script):
                result = tests.ReadableResult.parse(result_)
                assert result.clean_exit()
            assert cli_helpers.load_config() == config

    @tests.hypothesis_settings_coverage_compatible
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
        """Exporting configurations as sh(1) script works.

        Here, we check global-only configurations which use both
        settings settable via `--config` and settings requiring
        `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            'global': global_config_settable | global_config_importable,
            'services': {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)

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
        """Exporting configurations as sh(1) script works.

        Here, we check global-only configurations which only use
        settings requiring `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            'global': global_config_importable,
            'services': {},
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        if not config['global']:
            config.pop('global')
        return self.export_as_sh_helper(config)

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
        """Exporting configurations as sh(1) script works.

        Here, we check service-only configurations which use both
        settings settable via `--config` and settings requiring
        `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            'services': {
                service_name: (
                    service_config_settable | service_config_importable
                ),
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)

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
        """Exporting configurations as sh(1) script works.

        Here, we check service-only configurations which only use
        settings requiring `--import`.

        The actual verification is done by [`export_as_sh_helper`][].

        """
        config: _types.VaultConfig = {
            'services': {
                service_name: service_config_importable,
            },
        }
        assert _types.clean_up_falsy_vault_config_values(config) is not None
        assert _types.is_vault_config(config)
        return self.export_as_sh_helper(config)

    @pytest.mark.parametrize(
        ['command_line', 'config', 'result_config'],
        [
            pytest.param(
                ['--delete-globals'],
                {'global': {'phrase': 'abc'}, 'services': {}},
                {'services': {}},
                id='globals',
            ),
            pytest.param(
                ['--delete', '--', DUMMY_SERVICE],
                {
                    'global': {'phrase': 'abc'},
                    'services': {DUMMY_SERVICE: {'notes': '...'}},
                },
                {'global': {'phrase': 'abc'}, 'services': {}},
                id='service',
            ),
            pytest.param(
                ['--clear'],
                {
                    'global': {'phrase': 'abc'},
                    'services': {DUMMY_SERVICE: {'notes': '...'}},
                },
                {'services': {}},
                id='all',
            ),
        ],
    )
    def test_203_repeated_config_deletion(
        self,
        command_line: list[str],
        config: _types.VaultConfig,
        result_config: _types.VaultConfig,
    ) -> None:
        """Repeatedly removing the same parts of a configuration works."""
        for start_config in [config, result_config]:
            runner = click.testing.CliRunner(mix_stderr=False)
            # TODO(the-13th-letter): Rewrite using parenthesized
            # with-statements.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
            with contextlib.ExitStack() as stack:
                monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
                stack.enter_context(
                    tests.isolated_vault_config(
                        monkeypatch=monkeypatch,
                        runner=runner,
                        vault_config=start_config,
                    )
                )
                result_ = runner.invoke(
                    cli.derivepassphrase_vault,
                    command_line,
                    catch_exceptions=False,
                )
                result = tests.ReadableResult.parse(result_)
                assert result.clean_exit(empty_stderr=True), (
                    'expected clean exit'
                )
                with cli_helpers.config_filename(subsystem='vault').open(
                    encoding='UTF-8'
                ) as infile:
                    config_readback = json.load(infile)
                assert config_readback == result_config

    def test_204_phrase_from_key_manually(self) -> None:
        """The dummy service, key and config settings are consistent."""
        assert (
            vault.Vault(
                phrase=DUMMY_PHRASE_FROM_KEY1, **DUMMY_CONFIG_SETTINGS
            ).generate(DUMMY_SERVICE)
            == DUMMY_RESULT_KEY1
        )

    @pytest.mark.parametrize(
        ['vfunc', 'input'],
        [
            (cli_machinery.validate_occurrence_constraint, 20),
            (cli_machinery.validate_length, 20),
        ],
    )
    def test_210a_validate_constraints_manually(
        self,
        vfunc: Callable[[click.Context, click.Parameter, Any], int | None],
        input: int,
    ) -> None:
        """Command-line argument constraint validation works."""
        ctx = cli.derivepassphrase_vault.make_context(cli.PROG_NAME, [])
        param = cli.derivepassphrase_vault.params[0]
        assert vfunc(ctx, param, input) == input

    @pytest.mark.parametrize('conn_hint', ['none', 'socket', 'client'])
    def test_227_get_suitable_ssh_keys(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        conn_hint: str,
    ) -> None:
        """[`cli_helpers.get_suitable_ssh_keys`][] works."""
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv('SSH_AUTH_SOCK', running_ssh_agent.socket)
            monkeypatch.setattr(
                ssh_agent.SSHAgentClient, 'list_keys', tests.list_keys
            )
            hint: ssh_agent.SSHAgentClient | socket.socket | None
            # TODO(the-13th-letter): Rewrite using structural pattern
            # matching.
            # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
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
                list(cli_helpers.get_suitable_ssh_keys(hint))
            except RuntimeError:  # pragma: no cover
                pass
            except Exception as e:  # noqa: BLE001 # pragma: no cover
                exception = e
            finally:
                assert exception is None, (
                    'exception querying suitable SSH keys'
                )

    def test_400_key_to_phrase(
        self,
        skip_if_no_af_unix_support: None,
        ssh_agent_client_with_test_keys_loaded: ssh_agent.SSHAgentClient,
    ) -> None:
        """All errors in [`cli_helpers.key_to_phrase`][] are handled."""

        class ErrCallback(BaseException):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args[:1])
                self.args = args
                self.kwargs = kwargs

        def err(*args: Any, **_kwargs: Any) -> NoReturn:
            raise ErrCallback(*args, **_kwargs)

        def fail(*_args: Any, **_kwargs: Any) -> Any:
            raise ssh_agent.SSHAgentFailedError(
                _types.SSH_AGENT.FAILURE.value,
                b'',
            )

        def fail_runtime(*_args: Any, **_kwargs: Any) -> Any:
            raise ssh_agent.TrailingDataError()

        del skip_if_no_af_unix_support
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(ssh_agent.SSHAgentClient, 'sign', fail)
            loaded_keys = list(
                ssh_agent_client_with_test_keys_loaded.list_keys()
            )
            loaded_key = base64.standard_b64encode(loaded_keys[0][0])
            with monkeypatch.context() as mp:
                mp.setattr(
                    ssh_agent.SSHAgentClient,
                    'list_keys',
                    lambda *_a, **_kw: [],
                )
                with pytest.raises(
                    ErrCallback, match='not loaded into the agent'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            with monkeypatch.context() as mp:
                mp.setattr(ssh_agent.SSHAgentClient, 'list_keys', fail)
                with pytest.raises(
                    ErrCallback, match='SSH agent failed to or refused to'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            with monkeypatch.context() as mp:
                mp.setattr(ssh_agent.SSHAgentClient, 'list_keys', fail_runtime)
                with pytest.raises(
                    ErrCallback, match='SSH agent failed to or refused to'
                ) as excinfo:
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
                assert excinfo.value.kwargs
                assert isinstance(
                    excinfo.value.kwargs['exc_info'],
                    ssh_agent.SSHAgentFailedError,
                )
                assert excinfo.value.kwargs['exc_info'].__context__ is not None
                assert isinstance(
                    excinfo.value.kwargs['exc_info'].__context__,
                    ssh_agent.TrailingDataError,
                )
            with monkeypatch.context() as mp:
                mp.delenv('SSH_AUTH_SOCK', raising=True)
                with pytest.raises(
                    ErrCallback, match='Cannot find any running SSH agent'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            with monkeypatch.context() as mp:
                mp.setenv('SSH_AUTH_SOCK', os.environ['SSH_AUTH_SOCK'] + '~')
                with pytest.raises(
                    ErrCallback, match='Cannot connect to the SSH agent'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            with monkeypatch.context() as mp:
                mp.delattr(socket, 'AF_UNIX', raising=True)
                with pytest.raises(
                    ErrCallback, match='does not support UNIX domain sockets'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)
            with monkeypatch.context() as mp:
                mp.setattr(ssh_agent.SSHAgentClient, 'sign', fail_runtime)
                with pytest.raises(
                    ErrCallback, match='violates the communications protocol'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)


# TODO(the-13th-letter): Remove this class in v1.0.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#upgrading-to-v1.0
class TestCLITransition:
    """Transition tests for the command-line interface up to v1.0."""

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
        self,
        config: Any,
    ) -> None:
        """Loading the old settings file works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(config, indent=2) + '\n', encoding='UTF-8'
            )
            assert cli_helpers.migrate_and_load_old_config()[0] == config

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
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(config, indent=2) + '\n', encoding='UTF-8'
            )
            assert cli_helpers.migrate_and_load_old_config() == (config, None)

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
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file atop a directory fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(config, indent=2) + '\n', encoding='UTF-8'
            )
            cli_helpers.config_filename(subsystem='vault').mkdir(
                parents=True, exist_ok=True
            )
            config2, err = cli_helpers.migrate_and_load_old_config()
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
        self,
        config: Any,
    ) -> None:
        """Migrating an invalid old settings file fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(config, indent=2) + '\n', encoding='UTF-8'
            )
            with pytest.raises(ValueError, match=cli_helpers.INVALID_VAULT_CONFIG):
                cli_helpers.migrate_and_load_old_config()

    def test_200_forward_export_vault_path_parameter(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Forwarding arguments from "export" to "export vault" works."""
        pytest.importorskip('cryptography', minversion='38.0')
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
                cli.derivepassphrase,
                ['export', 'VAULT_PATH'],
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert json.loads(result.output) == tests.VAULT_V03_CONFIG_DATA

    def test_201_forward_export_vault_empty_commandline(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from "export" to "export vault" works."""
        pytest.importorskip('cryptography', minversion='38.0')
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                ['export'],
            )
        result = tests.ReadableResult.parse(result_)
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(error="Missing argument 'PATH'"), (
            'expected error exit and known error type'
        )

    @pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    def test_210_forward_vault_disable_character_set(
        self,
        caplog: pytest.LogCaptureFixture,
        charset_name: str,
    ) -> None:
        """Forwarding arguments from top-level to "vault" works."""
        option = f'--{charset_name}'
        charset = vault.Vault.CHARSETS[charset_name].decode('ascii')
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            monkeypatch.setattr(
                cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                [option, '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        for c in charset:
            assert c not in result.output, (
                f'derived password contains forbidden character {c!r}'
            )

    def test_211_forward_vault_empty_command_line(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from top-level to "vault" works."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            result_ = runner.invoke(
                cli.derivepassphrase,
                [],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            result = tests.ReadableResult.parse(result_)
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(
            error='Deriving a passphrase requires a SERVICE.'
        ), 'expected error exit and known error type'

    def test_300_export_using_old_config_file(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Exporting from (and migrating) the old settings file works."""
        caplog.set_level(logging.INFO)
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(
                    {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                    indent=2,
                )
                + '\n',
                encoding='UTF-8',
            )
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'v0.1-style config file', caplog.record_tuples
        ), 'expected known warning message in stderr'
        assert tests.deprecation_info_emitted(
            'Successfully migrated to ', caplog.record_tuples
        ), 'expected known warning message in stderr'

    def test_300a_export_using_old_config_file_migration_error(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Exporting from (and not migrating) the old settings file fails."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                )
            )
            cli_helpers.config_filename(subsystem='old settings.json').write_text(
                json.dumps(
                    {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                    indent=2,
                )
                + '\n',
                encoding='UTF-8',
            )

            def raiser(*_args: Any, **_kwargs: Any) -> None:
                raise OSError(
                    errno.EACCES,
                    os.strerror(errno.EACCES),
                    cli_helpers.config_filename(subsystem='vault'),
                )

            monkeypatch.setattr(os, 'replace', raiser)
            monkeypatch.setattr(pathlib.Path, 'rename', raiser)
            result_ = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'v0.1-style config file', caplog.record_tuples
        ), 'expected known warning message in stderr'
        assert tests.warning_emitted(
            'Failed to migrate to ', caplog.record_tuples
        ), 'expected known warning message in stderr'

    def test_400_completion_service_name_old_config_file(
        self,
    ) -> None:
        """Completing service names from the old settings file works."""
        config = {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}}
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            old_name = cli_helpers.config_filename(subsystem='old settings.json')
            new_name = cli_helpers.config_filename(subsystem='vault')
            old_name.unlink(missing_ok=True)
            new_name.rename(old_name)
            assert cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(['some_parameter']),
                '',
            ) == [DUMMY_SERVICE]


KNOWN_SERVICES = (DUMMY_SERVICE, 'email', 'bank', 'work')
"""Known service names.  Used for the [`ConfigManagementStateMachine`][]."""
VALID_PROPERTIES = (
    'length',
    'repeat',
    'upper',
    'lower',
    'number',
    'space',
    'dash',
    'symbol',
)
"""Known vault properties.  Used for the [`ConfigManagementStateMachine`][]."""


def build_reduced_vault_config_settings(
    config: _types.VaultConfigServicesSettings,
    keys_to_prune: frozenset[str],
) -> _types.VaultConfigServicesSettings:
    """Return a service settings object with certain keys pruned.

    Args:
        config:
            The original service settings object.
        keys_to_prune:
            The keys to prune from the settings object.

    """
    config2 = copy.deepcopy(config)
    for key in keys_to_prune:
        config2.pop(key, None)  # type: ignore[misc]
    return config2


SERVICES_STRATEGY = strategies.builds(
    build_reduced_vault_config_settings,
    tests.vault_full_service_config(),
    strategies.sets(
        strategies.sampled_from(VALID_PROPERTIES),
        max_size=7,
    ),
)
"""A hypothesis strategy to build incomplete service configurations."""


def services_strategy() -> strategies.SearchStrategy[
    _types.VaultConfigServicesSettings
]:
    """Return a strategy to build incomplete service configurations."""
    return SERVICES_STRATEGY


def assemble_config(
    global_data: _types.VaultConfigGlobalSettings,
    service_data: list[tuple[str, _types.VaultConfigServicesSettings]],
) -> _types.VaultConfig:
    """Return a vault config using the global and service data."""
    services_dict = dict(service_data)
    return (
        {'global': global_data, 'services': services_dict}
        if global_data
        else {'services': services_dict}
    )


@strategies.composite
def draw_service_name_and_data(
    draw: hypothesis.strategies.DrawFn,
    num_entries: int,
) -> tuple[tuple[str, _types.VaultConfigServicesSettings], ...]:
    """Draw a service name and settings, as a hypothesis strategy.

    Will draw service names from [`KNOWN_SERVICES`][] and service
    settings via [`services_strategy`][].

    Args:
        draw:
            The `draw` function, as provided for by hypothesis.
        num_entries:
            The number of services to draw.

    Returns:
        A sequence of pairs of service names and service settings.

    """
    possible_services = list(KNOWN_SERVICES)
    selected_services: list[str] = []
    for _ in range(num_entries):
        selected_services.append(
            draw(strategies.sampled_from(possible_services))
        )
        possible_services.remove(selected_services[-1])
    return tuple(
        (service, draw(services_strategy())) for service in selected_services
    )


VAULT_FULL_CONFIG = strategies.builds(
    assemble_config,
    services_strategy(),
    strategies.integers(
        min_value=2,
        max_value=4,
    ).flatmap(draw_service_name_and_data),
)
"""A hypothesis strategy to build full vault configurations."""


def vault_full_config() -> strategies.SearchStrategy[_types.VaultConfig]:
    """Return a strategy to build full vault configurations."""
    return VAULT_FULL_CONFIG


@tests.hypothesis_settings_coverage_compatible
class ConfigManagementStateMachine(stateful.RuleBasedStateMachine):
    """A state machine recording changes in the vault configuration.

    Record possible configuration states in bundles, then in each rule,
    take a configuration and manipulate it somehow.

    Attributes:
        setting:
            A bundle for single-service settings.
        configuration:
            A bundle for full vault configurations.

    """

    def __init__(self) -> None:
        """Initialize self, set up context managers and enter them."""
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

    setting: stateful.Bundle[_types.VaultConfigServicesSettings] = (
        stateful.Bundle('setting')
    )
    """"""
    configuration: stateful.Bundle[_types.VaultConfig] = stateful.Bundle(
        'configuration'
    )
    """"""

    @stateful.initialize(
        target=configuration,
        configs=strategies.lists(
            vault_full_config(),
            min_size=8,
            max_size=8,
        ),
    )
    def declare_initial_configs(
        self,
        configs: Iterable[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfig]:
        """Initialize the configuration bundle with eight configurations."""
        return stateful.multiple(*configs)

    @stateful.initialize(
        target=setting,
        configs=strategies.lists(
            vault_full_config(),
            min_size=4,
            max_size=4,
        ),
    )
    def extract_initial_settings(
        self,
        configs: list[_types.VaultConfig],
    ) -> stateful.MultipleResults[_types.VaultConfigServicesSettings]:
        """Initialize the settings bundle with four service settings."""
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
            strategies.sampled_from(VALID_PROPERTIES),
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
        """Set the global settings of a configuration.

        Args:
            config:
                The configuration to edit.
            setting:
                The new global settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The amended configuration.

        """
        cli_helpers.save_config(config)
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
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                '--config',
                '--overwrite-existing' if overwrite else '--merge-existing',
            ]
            + [f'--unset={key}' for key in maybe_unset]
            + [
                f'--{key}={value}'
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ],
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
        service=strategies.sampled_from(KNOWN_SERVICES),
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
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
        """Set the named service settings for a configuration.

        Args:
            config:
                The configuration to edit.
            service:
                The name of the service to set.
            setting:
                The new service settings.
            maybe_unset:
                Settings keys to additionally unset, if not already
                present in the new settings.  Corresponds to the
                `--unset` command-line argument.
            overwrite:
                Overwrite the settings object if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The amended configuration.

        """
        cli_helpers.save_config(config)
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
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            [
                '--config',
                '--overwrite-existing' if overwrite else '--merge-existing',
            ]
            + [f'--unset={key}' for key in maybe_unset]
            + [
                f'--{key}={value}'
                for key, value in setting.items()
                if key in VALID_PROPERTIES
            ]
            + ['--', service],
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_global(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        """Purge the globals of a configuration.

        Args:
            config:
                The configuration to edit.

        Returns:
            The pruned configuration.

        """
        cli_helpers.save_config(config)
        config.pop('global', None)
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete-globals'],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
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
        """Purge the settings of a named service in a configuration.

        Args:
            config_and_service:
                A 2-tuple containing the configuration to edit, and the
                service name to purge.

        Returns:
            The pruned configuration.

        """
        config, service = config_and_service
        cli_helpers.save_config(config)
        config['services'].pop(service, None)
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete', '--', service],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    @stateful.rule(
        target=configuration,
        config=configuration,
    )
    def purge_all(
        self,
        config: _types.VaultConfig,
    ) -> _types.VaultConfig:
        """Purge the entire configuration.

        Args:
            config:
                The configuration to edit.

        Returns:
            The empty configuration.

        """
        cli_helpers.save_config(config)
        config = {'services': {}}
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--clear'],
            input='y',
            catch_exceptions=False,
        )
        result = tests.ReadableResult.parse(result_)
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
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
        """Import the given configuration into a base configuration.

        Args:
            base_config:
                The configuration to import into.
            config_to_import:
                The configuration to import.
            overwrite:
                Overwrite the base configuration if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        Returns:
            The imported or merged configuration.

        """
        cli_helpers.save_config(base_config)
        config = (
            self.fold_configs(config_to_import, base_config)
            if not overwrite
            else config_to_import
        )
        assert _types.is_vault_config(config)
        result_ = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--import', '-']
            + (['--overwrite-existing'] if overwrite else []),
            input=json.dumps(config_to_import),
            catch_exceptions=False,
        )
        assert tests.ReadableResult.parse(result_).clean_exit(
            empty_stderr=False
        )
        assert cli_helpers.load_config() == config
        return config

    def teardown(self) -> None:
        """Upon teardown, exit all contexts entered in `__init__`."""
        self.exit_stack.close()


TestConfigManagement = ConfigManagementStateMachine.TestCase
"""The [`unittest.TestCase`][] class that will actually be run."""


def bash_format(item: click.shell_completion.CompletionItem) -> str:
    """A formatter for `bash`-style shell completion items.

    The format is `type,value`, and is dictated by [`click`][].

    """
    type, value = (  # noqa: A001
        item.type,
        item.value,
    )
    return f'{type},{value}'


def fish_format(item: click.shell_completion.CompletionItem) -> str:
    r"""A formatter for `fish`-style shell completion items.

    The format is `type,value<tab>help`, and is dictated by [`click`][].

    """
    type, value, help = (  # noqa: A001
        item.type,
        item.value,
        item.help,
    )
    return f'{type},{value}\t{help}' if help else f'{type},{value}'


def zsh_format(item: click.shell_completion.CompletionItem) -> str:
    r"""A formatter for `zsh`-style shell completion items.

    The format is `type<newline>value<newline>help<newline>`, and is
    dictated by [`click`][].  Upstream `click` currently (v8.2.0) does
    not deal with colons in the value correctly when the help text is
    non-degenerate.  Our formatter here does, provided the upstream
    `zsh` completion script is used; see the
    [`cli_machinery.ZshComplete`][] class.  A request is underway to
    merge this change into upstream `click`; see
    [`pallets/click#2846`][PR2846].

    [PR2846]: https://github.com/pallets/click/pull/2846

    """
    empty_help = '_'
    help_, value = (
        (item.help, item.value.replace(':', r'\:'))
        if item.help and item.help == empty_help
        else (empty_help, item.value)
    )
    return f'{item.type}\n{value}\n{help_}'


def completion_item(
    item: str | click.shell_completion.CompletionItem,
) -> click.shell_completion.CompletionItem:
    """Convert a string to a completion item, if necessary."""
    return (
        click.shell_completion.CompletionItem(item, type='plain')
        if isinstance(item, str)
        else item
    )


def assertable_item(
    item: str | click.shell_completion.CompletionItem,
) -> tuple[str, Any, str | None]:
    """Convert a completion item into a pretty-printable item.

    Intended to make completion items introspectable in pytest's
    `assert` output.

    """
    item = completion_item(item)
    return (item.type, item.value, item.help)


class TestShellCompletion:
    """Tests for the shell completion machinery."""

    class Completions:
        """A deferred completion call."""

        def __init__(
            self,
            args: Sequence[str],
            incomplete: str,
        ) -> None:
            """Initialize the object.

            Args:
                args:
                    The sequence of complete command-line arguments.
                incomplete:
                    The final, incomplete, partial argument.

            """
            self.args = tuple(args)
            self.incomplete = incomplete

        def __call__(self) -> Sequence[click.shell_completion.CompletionItem]:
            """Return the completion items."""
            args = list(self.args)
            completion = click.shell_completion.ShellComplete(
                cli=cli.derivepassphrase,
                ctx_args={},
                prog_name='derivepassphrase',
                complete_var='_DERIVEPASSPHRASE_COMPLETE',
            )
            return completion.get_completions(args, self.incomplete)

        def get_words(self) -> Sequence[str]:
            """Return the completion items' values, as a sequence."""
            return tuple(c.value for c in self())

    @pytest.mark.parametrize(
        ['partial', 'is_completable'],
        [
            ('', True),
            (DUMMY_SERVICE, True),
            ('a\bn', False),
            ('\b', False),
            ('\x00', False),
            ('\x20', True),
            ('\x7f', False),
            ('service with spaces', True),
            ('service\nwith\nnewlines', False),
        ],
    )
    def test_100_is_completable_item(
        self,
        partial: str,
        is_completable: bool,
    ) -> None:
        """Our `_is_completable_item` predicate for service names works."""
        assert cli_helpers.is_completable_item(partial) == is_completable

    @pytest.mark.parametrize(
        ['command_prefix', 'incomplete', 'completions'],
        [
            pytest.param(
                (),
                '-',
                frozenset({
                    '--help',
                    '-h',
                    '--version',
                    '--debug',
                    '--verbose',
                    '-v',
                    '--quiet',
                    '-q',
                }),
                id='derivepassphrase',
            ),
            pytest.param(
                ('export',),
                '-',
                frozenset({
                    '--help',
                    '-h',
                    '--version',
                    '--debug',
                    '--verbose',
                    '-v',
                    '--quiet',
                    '-q',
                }),
                id='derivepassphrase-export',
            ),
            pytest.param(
                ('export', 'vault'),
                '-',
                frozenset({
                    '--help',
                    '-h',
                    '--version',
                    '--debug',
                    '--verbose',
                    '-v',
                    '--quiet',
                    '-q',
                    '--format',
                    '-f',
                    '--key',
                    '-k',
                }),
                id='derivepassphrase-export-vault',
            ),
            pytest.param(
                ('vault',),
                '-',
                frozenset({
                    '--help',
                    '-h',
                    '--version',
                    '--debug',
                    '--verbose',
                    '-v',
                    '--quiet',
                    '-q',
                    '--phrase',
                    '-p',
                    '--key',
                    '-k',
                    '--length',
                    '-l',
                    '--repeat',
                    '-r',
                    '--upper',
                    '--lower',
                    '--number',
                    '--space',
                    '--dash',
                    '--symbol',
                    '--config',
                    '-c',
                    '--notes',
                    '-n',
                    '--delete',
                    '-x',
                    '--delete-globals',
                    '--clear',
                    '-X',
                    '--export',
                    '-e',
                    '--import',
                    '-i',
                    '--overwrite-existing',
                    '--merge-existing',
                    '--unset',
                    '--export-as',
                }),
                id='derivepassphrase-vault',
            ),
        ],
    )
    def test_200_options(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' options."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @pytest.mark.parametrize(
        ['command_prefix', 'incomplete', 'completions'],
        [
            pytest.param(
                (),
                '',
                frozenset({'export', 'vault'}),
                id='derivepassphrase',
            ),
            pytest.param(
                ('export',),
                '',
                frozenset({'vault'}),
                id='derivepassphrase-export',
            ),
        ],
    )
    def test_201_subcommands(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' subcommands."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @pytest.mark.parametrize(
        'command_prefix',
        [
            pytest.param(
                ('export', 'vault'),
                id='derivepassphrase-export-vault',
            ),
            pytest.param(
                ('vault', '--export'),
                id='derivepassphrase-vault--export',
            ),
            pytest.param(
                ('vault', '--import'),
                id='derivepassphrase-vault--import',
            ),
        ],
    )
    @pytest.mark.parametrize('incomplete', ['', 'partial'])
    def test_202_paths(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
    ) -> None:
        """Our completion machinery works for all commands' paths."""
        file = click.shell_completion.CompletionItem('', type='file')
        completions = frozenset({(file.type, file.value, file.help)})
        comp = self.Completions(command_prefix, incomplete)
        assert (
            frozenset((x.type, x.value, x.help) for x in comp()) == completions
        )

    @pytest.mark.parametrize(
        ['config', 'incomplete', 'completions'],
        [
            pytest.param(
                {'services': {}},
                '',
                frozenset(),
                id='no_services',
            ),
            pytest.param(
                {'services': {}},
                'partial',
                frozenset(),
                id='no_services_partial',
            ),
            pytest.param(
                {'services': {DUMMY_SERVICE: {'length': 10}}},
                '',
                frozenset({DUMMY_SERVICE}),
                id='one_service',
            ),
            pytest.param(
                {'services': {DUMMY_SERVICE: {'length': 10}}},
                DUMMY_SERVICE[:4],
                frozenset({DUMMY_SERVICE}),
                id='one_service_partial',
            ),
            pytest.param(
                {'services': {DUMMY_SERVICE: {'length': 10}}},
                DUMMY_SERVICE[-4:],
                frozenset(),
                id='one_service_partial_miss',
            ),
        ],
    )
    def test_203_service_names(
        self,
        config: _types.VaultConfig,
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for vault service names."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            comp = self.Completions(['vault'], incomplete)
            assert frozenset(comp.get_words()) == completions

    @pytest.mark.parametrize(
        ['shell', 'format_func'],
        [
            pytest.param('bash', bash_format, id='bash'),
            pytest.param('fish', fish_format, id='fish'),
            pytest.param('zsh', zsh_format, id='zsh'),
        ],
    )
    @pytest.mark.parametrize(
        ['config', 'comp_func', 'args', 'incomplete', 'results'],
        [
            pytest.param(
                {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}},
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                [DUMMY_SERVICE],
                id='base_config-service',
            ),
            pytest.param(
                {'services': {}},
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                [],
                id='empty_config-service',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'newline\nin\nname': DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                [DUMMY_SERVICE],
                id='incompletable_newline_config-service',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'backspace\bin\bname': DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                [DUMMY_SERVICE],
                id='incompletable_backspace_config-service',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'colon:in:name': DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                sorted([DUMMY_SERVICE, 'colon:in:name']),
                id='brittle_colon_config-service',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        'colon:in:name': DUMMY_CONFIG_SETTINGS.copy(),
                        'newline\nin\nname': DUMMY_CONFIG_SETTINGS.copy(),
                        'backspace\bin\bname': DUMMY_CONFIG_SETTINGS.copy(),
                        'nul\x00in\x00name': DUMMY_CONFIG_SETTINGS.copy(),
                        'del\x7fin\x7fname': DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ['vault'],
                '',
                sorted([DUMMY_SERVICE, 'colon:in:name']),
                id='brittle_incompletable_multi_config-service',
            ),
            pytest.param(
                {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}},
                cli_helpers.shell_complete_path,
                ['vault', '--import'],
                '',
                [click.shell_completion.CompletionItem('', type='file')],
                id='base_config-path',
            ),
            pytest.param(
                {'services': {}},
                cli_helpers.shell_complete_path,
                ['vault', '--import'],
                '',
                [click.shell_completion.CompletionItem('', type='file')],
                id='empty_config-path',
            ),
        ],
    )
    def test_300_shell_completion_formatting(
        self,
        shell: str,
        format_func: Callable[[click.shell_completion.CompletionItem], str],
        config: _types.VaultConfig,
        comp_func: Callable[
            [click.Context, click.Parameter, str],
            list[str | click.shell_completion.CompletionItem],
        ],
        args: list[str],
        incomplete: str,
        results: list[str | click.shell_completion.CompletionItem],
    ) -> None:
        """Custom completion functions work for all shells."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            expected_items = [assertable_item(item) for item in results]
            expected_string = '\n'.join(
                format_func(completion_item(item)) for item in results
            )
            manual_raw_items = comp_func(
                click.Context(cli.derivepassphrase),
                click.Argument(['sample_parameter']),
                incomplete,
            )
            manual_items = [assertable_item(item) for item in manual_raw_items]
            manual_string = '\n'.join(
                format_func(completion_item(item)) for item in manual_raw_items
            )
            assert manual_items == expected_items
            assert manual_string == expected_string
            comp_class = click.shell_completion.get_completion_class(shell)
            assert comp_class is not None
            comp = comp_class(
                cli.derivepassphrase,
                {},
                'derivepassphrase',
                '_DERIVEPASSPHRASE_COMPLETE',
            )
            monkeypatch.setattr(
                comp,
                'get_completion_args',
                lambda *_a, **_kw: (args, incomplete),
            )
            actual_raw_items = comp.get_completions(
                *comp.get_completion_args()
            )
            actual_items = [assertable_item(item) for item in actual_raw_items]
            actual_string = comp.complete()
            assert actual_items == expected_items
            assert actual_string == expected_string

    @pytest.mark.parametrize('mode', ['config', 'import'])
    @pytest.mark.parametrize(
        ['config', 'key', 'incomplete', 'completions'],
        [
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'newline\nin\nname': {'length': 10},
                    },
                },
                'newline\nin\nname',
                '',
                frozenset({DUMMY_SERVICE}),
                id='newline',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'newline\nin\nname': {'length': 10},
                    },
                },
                'newline\nin\nname',
                'serv',
                frozenset({DUMMY_SERVICE}),
                id='newline_partial_other',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'newline\nin\nname': {'length': 10},
                    },
                },
                'newline\nin\nname',
                'newline',
                frozenset({}),
                id='newline_partial_specific',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'nul\x00in\x00name': {'length': 10},
                    },
                },
                'nul\x00in\x00name',
                '',
                frozenset({DUMMY_SERVICE}),
                id='nul',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'nul\x00in\x00name': {'length': 10},
                    },
                },
                'nul\x00in\x00name',
                'serv',
                frozenset({DUMMY_SERVICE}),
                id='nul_partial_other',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'nul\x00in\x00name': {'length': 10},
                    },
                },
                'nul\x00in\x00name',
                'nul',
                frozenset({}),
                id='nul_partial_specific',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'backspace\bin\bname': {'length': 10},
                    },
                },
                'backspace\bin\bname',
                '',
                frozenset({DUMMY_SERVICE}),
                id='backspace',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'backspace\bin\bname': {'length': 10},
                    },
                },
                'backspace\bin\bname',
                'serv',
                frozenset({DUMMY_SERVICE}),
                id='backspace_partial_other',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'backspace\bin\bname': {'length': 10},
                    },
                },
                'backspace\bin\bname',
                'back',
                frozenset({}),
                id='backspace_partial_specific',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'del\x7fin\x7fname': {'length': 10},
                    },
                },
                'del\x7fin\x7fname',
                '',
                frozenset({DUMMY_SERVICE}),
                id='del',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'del\x7fin\x7fname': {'length': 10},
                    },
                },
                'del\x7fin\x7fname',
                'serv',
                frozenset({DUMMY_SERVICE}),
                id='del_partial_other',
            ),
            pytest.param(
                {
                    'services': {
                        DUMMY_SERVICE: {'length': 10},
                        'del\x7fin\x7fname': {'length': 10},
                    },
                },
                'del\x7fin\x7fname',
                'del',
                frozenset({}),
                id='del_partial_specific',
            ),
        ],
    )
    def test_400_incompletable_service_names(
        self,
        caplog: pytest.LogCaptureFixture,
        mode: Literal['config', 'import'],
        config: _types.VaultConfig,
        key: str,
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Completion skips incompletable items."""
        vault_config = config if mode == 'config' else {'services': {}}
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                )
            )
            if mode == 'config':
                result_ = runner.invoke(
                    cli.derivepassphrase_vault,
                    ['--config', '--length=10', '--', key],
                    catch_exceptions=False,
                )
            else:
                result_ = runner.invoke(
                    cli.derivepassphrase_vault,
                    ['--import', '-'],
                    catch_exceptions=False,
                    input=json.dumps(config),
                )
            result = tests.ReadableResult.parse(result_)
            assert result.clean_exit(), 'expected clean exit'
            assert tests.warning_emitted(
                'contains an ASCII control character', caplog.record_tuples
            ), 'expected known warning message in stderr'
            assert tests.warning_emitted(
                'not be available for completion', caplog.record_tuples
            ), 'expected known warning message in stderr'
            assert cli_helpers.load_config() == config
            comp = self.Completions(['vault'], incomplete)
            assert frozenset(comp.get_words()) == completions

    def test_410a_service_name_exceptions_not_found(
        self,
    ) -> None:
        """Service name completion quietly fails on missing configuration."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )
            cli_helpers.config_filename(subsystem='vault').unlink(missing_ok=True)
            assert not cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(['some_parameter']),
                '',
            )

    @pytest.mark.parametrize('exc_type', [RuntimeError, KeyError, ValueError])
    def test_410b_service_name_exceptions_custom_error(
        self,
        exc_type: type[Exception],
    ) -> None:
        """Service name completion quietly fails on configuration errors."""
        runner = click.testing.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )

            def raiser(*_a: Any, **_kw: Any) -> NoReturn:
                raise exc_type('just being difficult')  # noqa: EM101,TRY003

            monkeypatch.setattr(cli_helpers, 'load_config', raiser)
            assert not cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(['some_parameter']),
                '',
            )
