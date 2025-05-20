# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import base64
import contextlib
import copy
import enum
import errno
import io
import json
import logging
import os
import pathlib
import queue
import re
import shlex
import shutil
import socket
import tempfile
import textwrap
import types
import warnings
from typing import TYPE_CHECKING, cast

import click.testing
import hypothesis
import pytest
from hypothesis import stateful, strategies
from typing_extensions import Any, NamedTuple, TypeAlias

import tests
from derivepassphrase import _types, cli, ssh_agent, vault
from derivepassphrase._internals import (
    cli_helpers,
    cli_machinery,
    cli_messages,
)

if TYPE_CHECKING:
    import multiprocessing
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


class VersionOutputData(NamedTuple):
    derivation_schemes: dict[str, bool]
    foreign_configuration_formats: dict[str, bool]
    extras: frozenset[str]
    subcommands: frozenset[str]
    features: dict[str, bool]


class KnownLineType(str, enum.Enum):
    SUPPORTED_FOREIGN_CONFS = cli_messages.Label.SUPPORTED_FOREIGN_CONFIGURATION_FORMATS.value.singular.rstrip(
        ':'
    )
    UNAVAILABLE_FOREIGN_CONFS = cli_messages.Label.UNAVAILABLE_FOREIGN_CONFIGURATION_FORMATS.value.singular.rstrip(
        ':'
    )
    SUPPORTED_SCHEMES = (
        cli_messages.Label.SUPPORTED_DERIVATION_SCHEMES.value.singular.rstrip(
            ':'
        )
    )
    UNAVAILABLE_SCHEMES = cli_messages.Label.UNAVAILABLE_DERIVATION_SCHEMES.value.singular.rstrip(
        ':'
    )
    SUPPORTED_SUBCOMMANDS = (
        cli_messages.Label.SUPPORTED_SUBCOMMANDS.value.singular.rstrip(':')
    )
    SUPPORTED_FEATURES = (
        cli_messages.Label.SUPPORTED_FEATURES.value.singular.rstrip(':')
    )
    UNAVAILABLE_FEATURES = (
        cli_messages.Label.UNAVAILABLE_FEATURES.value.singular.rstrip(':')
    )
    ENABLED_EXTRAS = (
        cli_messages.Label.ENABLED_PEP508_EXTRAS.value.singular.rstrip(':')
    )


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
        CONFIGURATION_COMMANDS + STORAGE_OPTIONS, True, None
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


def assert_vault_config_is_indented_and_line_broken(
    config_txt: str,
    /,
) -> None:
    """Return true if the vault configuration is indented and line broken.

    Indented and rewrapped vault configurations as produced by
    `json.dump` contain the closing '}' of the '$.services' object
    on a separate, indented line:

    ~~~~
    {
      "services": {
        ...
      }  <-- this brace here
    }
    ~~~~

    or, if there are no services, then the indented line

    ~~~~
      "services": {}
    ~~~~

    Both variations may end with a comma if there are more top-level
    keys.

    """
    known_indented_lines = {
        '}',
        '},',
        '"services": {}',
        '"services": {},',
    }
    assert any([
        line.strip() in known_indented_lines and line.startswith((' ', '\t'))
        for line in config_txt.splitlines()
    ])


def vault_config_exporter_shell_interpreter(  # noqa: C901
    script: str | Iterable[str],
    /,
    *,
    prog_name_list: list[str] | None = None,
    command: click.BaseCommand | None = None,
    runner: tests.CliRunner | None = None,
) -> Iterator[tests.ReadableResult]:
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
        runner = tests.CliRunner(mix_stderr=False)
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


def parse_version_output(  # noqa: C901
    version_output: str,
    /,
    *,
    prog_name: str | None = cli_messages.PROG_NAME,
    version: str | None = cli_messages.VERSION,
) -> VersionOutputData:
    r"""Parse the output of the `--version` option.

    The version output contains two paragraphs.  The first paragraph
    details the version number, and the version number of any major
    libraries in use.  The second paragraph details known and supported
    passphrase derivation schemes, foreign configuration formats,
    subcommands and PEP 508 package extras.  For the schemes and
    formats, there is a "supported" line for supported items, and
    a "known" line for known but currently unsupported items (usually
    because of missing dependencies), either of which may be empty and
    thus omitted.  For extras, only active items are shown, and there is
    a separate message for the "no extras active" case.  Item lists may
    be spilled across multiple lines, but only at item boundaries, and
    the continuation lines are then indented.

    Args:
        version_output:
            The version output text to parse.
        prog_name:
            The program name to assert, defaulting to the true program
            name, `derivepassphrase`.  Set to `None` to disable this
            check.
        version:
            The program version to assert, defaulting to the true
            current version of `derivepassphrase`.  Set to `None` to
            disable this check.

    Examples:
        See [`Parametrize.VERSION_OUTPUT_DATA`][].

    """
    paragraphs: list[list[str]] = []
    paragraph: list[str] = []
    for line in version_output.splitlines(keepends=False):
        if not line.strip():
            if paragraph:
                paragraphs.append(paragraph.copy())
            paragraph.clear()
        elif paragraph and line.lstrip() != line:
            paragraph[-1] = f'{paragraph[-1]} {line.lstrip()}'
        else:
            paragraph.append(line)
    if paragraph:  # pragma: no branch
        paragraphs.append(paragraph.copy())
        paragraph.clear()
    assert paragraphs, (
        f'expected at least one paragraph of version output: {paragraphs!r}'
    )
    assert prog_name is None or prog_name in paragraphs[0][0], (
        f'first version output line should mention '
        f'{prog_name}: {paragraphs[0][0]!r}'
    )
    assert version is None or version in paragraphs[0][0], (
        f'first version output line should mention the version number '
        f'{version}: {paragraphs[0][0]!r}'
    )
    schemes: dict[str, bool] = {}
    formats: dict[str, bool] = {}
    subcommands: set[str] = set()
    extras: set[str] = set()
    features: dict[str, bool] = {}
    if len(paragraphs) < 2:  # pragma: no cover
        return VersionOutputData(
            derivation_schemes=schemes,
            foreign_configuration_formats=formats,
            subcommands=frozenset(subcommands),
            extras=frozenset(extras),
            features=features,
        )
    for line in paragraphs[1]:
        line_type, _, value = line.partition(':')
        if line_type == line:
            continue
        for item_ in re.split(r'(?:, *|.$)', value):
            item = item_.strip()
            if not item:
                continue
            if line_type == KnownLineType.SUPPORTED_FOREIGN_CONFS:
                formats[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_FOREIGN_CONFS:
                formats[item] = False
            elif line_type == KnownLineType.SUPPORTED_SCHEMES:
                schemes[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_SCHEMES:
                schemes[item] = False
            elif line_type == KnownLineType.SUPPORTED_SUBCOMMANDS:
                subcommands.add(item)
            elif line_type == KnownLineType.ENABLED_EXTRAS:
                extras.add(item)
            elif line_type == KnownLineType.SUPPORTED_FEATURES:
                features[item] = True
            elif line_type == KnownLineType.UNAVAILABLE_FEATURES:
                features[item] = False
            else:
                raise AssertionError(  # noqa: TRY003
                    f'Unknown version info line type: {line_type!r}'  # noqa: EM102
                )
    return VersionOutputData(
        derivation_schemes=schemes,
        foreign_configuration_formats=formats,
        subcommands=frozenset(subcommands),
        extras=frozenset(extras),
        features=features,
    )


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


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    EAGER_ARGUMENTS = pytest.mark.parametrize(
        'arguments',
        [['--help'], ['--version']],
        ids=['help', 'version'],
    )
    CHARSET_NAME = pytest.mark.parametrize(
        'charset_name', ['lower', 'upper', 'number', 'space', 'dash', 'symbol']
    )
    COMMAND_NON_EAGER_ARGUMENTS = pytest.mark.parametrize(
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
    UNICODE_NORMALIZATION_COMMAND_LINES = pytest.mark.parametrize(
        'command_line',
        [
            pytest.param(
                ['--config', '--phrase'],
                id='configure global passphrase',
            ),
            pytest.param(
                ['--config', '--phrase', '--', 'DUMMY_SERVICE'],
                id='configure service passphrase',
            ),
            pytest.param(
                ['--phrase', '--', DUMMY_SERVICE],
                id='interactive passphrase',
            ),
        ],
    )
    DELETE_CONFIG_INPUT = pytest.mark.parametrize(
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
    COLORFUL_COMMAND_INPUT = pytest.mark.parametrize(
        ['command_line', 'input'],
        [
            (
                ['vault', '--import', '-'],
                '{"services": {"": {"length": 20}}}',
            ),
        ],
        ids=['cmd'],
    )
    CONFIG_EDITING_VIA_CONFIG_FLAG_FAILURES = pytest.mark.parametrize(
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
    CONFIG_EDITING_VIA_CONFIG_FLAG = pytest.mark.parametrize(
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
    COMPLETABLE_PATH_ARGUMENT = pytest.mark.parametrize(
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
    COMPLETABLE_OPTIONS = pytest.mark.parametrize(
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
                    '--modern-editor-interface',
                    '--vault-legacy-editor-interface',
                    '--print-notes-before',
                    '--print-notes-after',
                }),
                id='derivepassphrase-vault',
            ),
        ],
    )
    COMPLETABLE_SUBCOMMANDS = pytest.mark.parametrize(
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
    BAD_CONFIGS = pytest.mark.parametrize(
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
    BASE_CONFIG_VARIATIONS = pytest.mark.parametrize(
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
    BASE_CONFIG_WITH_KEY_VARIATIONS = pytest.mark.parametrize(
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
    CONFIG_WITH_KEY = pytest.mark.parametrize(
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
    VALID_TEST_CONFIGS = pytest.mark.parametrize(
        'config',
        [
            conf.config
            for conf in TEST_CONFIGS
            if tests.is_valid_test_config(conf)
        ],
    )
    KEY_OVERRIDING_IN_CONFIG = pytest.mark.parametrize(
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
    COMPLETION_FUNCTION_INPUTS = pytest.mark.parametrize(
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
    COMPLETABLE_SERVICE_NAMES = pytest.mark.parametrize(
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
    SERVICE_NAME_COMPLETION_INPUTS = pytest.mark.parametrize(
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
    CONNECTION_HINTS = pytest.mark.parametrize(
        'conn_hint', ['none', 'socket', 'client']
    )
    NOOP_EDIT_FUNCS = pytest.mark.parametrize(
        ['edit_func_name', 'modern_editor_interface'],
        [
            pytest.param('empty', True, id='empty'),
            pytest.param('space', False, id='space-legacy'),
            pytest.param('space', True, id='space-modern'),
        ],
    )
    SERVICE_NAME_EXCEPTIONS = pytest.mark.parametrize(
        'exc_type', [RuntimeError, KeyError, ValueError]
    )
    EXPORT_FORMAT_OPTIONS = pytest.mark.parametrize(
        'export_options',
        [
            [],
            ['--export-as=sh'],
        ],
    )
    FORCE_COLOR = pytest.mark.parametrize(
        'force_color',
        [False, True],
        ids=['noforce', 'force'],
    )
    INCOMPLETE = pytest.mark.parametrize('incomplete', ['', 'partial'])
    ISATTY = pytest.mark.parametrize(
        'isatty',
        [False, True],
        ids=['notty', 'tty'],
    )
    KEY_INDEX = pytest.mark.parametrize(
        'key_index', [1, 2, 3], ids=lambda i: f'index{i}'
    )
    UNICODE_NORMALIZATION_ERROR_INPUTS = pytest.mark.parametrize(
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
    UNICODE_NORMALIZATION_WARNING_INPUTS = pytest.mark.parametrize(
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
    MASK_PROG_NAME = pytest.mark.parametrize('mask_prog_name', [False, True])
    MASK_VERSION = pytest.mark.parametrize('mask_version', [False, True])
    CONFIG_SETTING_MODE = pytest.mark.parametrize('mode', ['config', 'import'])
    MODERN_EDITOR_INTERFACE = pytest.mark.parametrize(
        'modern_editor_interface', [False, True], ids=['legacy', 'modern']
    )
    NO_COLOR = pytest.mark.parametrize(
        'no_color',
        [False, True],
        ids=['yescolor', 'nocolor'],
    )
    NOTES_PLACEMENT = pytest.mark.parametrize(
        ['notes_placement', 'placement_args'],
        [
            pytest.param('after', ['--print-notes-after'], id='after'),
            pytest.param('before', ['--print-notes-before'], id='before'),
        ],
    )
    VAULT_CHARSET_OPTION = pytest.mark.parametrize(
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
    OPTION_COMBINATIONS_INCOMPATIBLE = pytest.mark.parametrize(
        ['options', 'service'],
        [
            pytest.param(o.options, o.needs_service, id=' '.join(o.options))
            for o in INTERESTING_OPTION_COMBINATIONS
            if o.incompatible
        ],
    )
    OPTION_COMBINATIONS_SERVICE_NEEDED = pytest.mark.parametrize(
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
    COMPLETABLE_ITEMS = pytest.mark.parametrize(
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
    SHELL_FORMATTER = pytest.mark.parametrize(
        ['shell', 'format_func'],
        [
            pytest.param('bash', bash_format, id='bash'),
            pytest.param('fish', fish_format, id='fish'),
            pytest.param('zsh', zsh_format, id='zsh'),
        ],
    )
    TRY_RACE_FREE_IMPLEMENTATION = pytest.mark.parametrize(
        'try_race_free_implementation', [True, False]
    )
    VERSION_OUTPUT_DATA = pytest.mark.parametrize(
        ['version_output', 'prog_name', 'version', 'expected_parse'],
        [
            pytest.param(
                """\
derivepassphrase 0.4.0
Using cryptography 44.0.0

Supported foreign configuration formats: vault storeroom, vault v0.2,
    vault v0.3.
PEP 508 extras: export.
""",
                'derivepassphrase',
                '0.4.0',
                VersionOutputData(
                    derivation_schemes={},
                    foreign_configuration_formats={
                        'vault storeroom': True,
                        'vault v0.2': True,
                        'vault v0.3': True,
                    },
                    subcommands=frozenset(),
                    features={},
                    extras=frozenset({'export'}),
                ),
                id='derivepassphrase-0.4.0-export',
            ),
            pytest.param(
                """\
derivepassphrase 0.5

Supported derivation schemes: vault.
Known foreign configuration formats: vault storeroom, vault v0.2, vault v0.3.
Supported subcommands: export, vault.
No PEP 508 extras are active.
""",
                'derivepassphrase',
                '0.5',
                VersionOutputData(
                    derivation_schemes={'vault': True},
                    foreign_configuration_formats={
                        'vault storeroom': False,
                        'vault v0.2': False,
                        'vault v0.3': False,
                    },
                    subcommands=frozenset({'export', 'vault'}),
                    features={},
                    extras=frozenset({}),
                ),
                id='derivepassphrase-0.5-plain',
            ),
            pytest.param(
                """\



inventpassphrase -1.3
Using not-a-library 7.12
Copyright 2025 Nobody.  All rights reserved.

Supported derivation schemes: nonsense.
Known derivation schemes: divination, /dev/random,
    geiger counter,
    crossword solver.
Supported foreign configuration formats: derivepassphrase, nonsense.
Known foreign configuration formats: divination v3.141592,
    /dev/random.
Supported subcommands: delete-all-files, dump-core.
Supported features: delete-while-open.
Known features: backups-are-nice-to-have.
PEP 508 extras: annoying-popups, delete-all-files,
    dump-core-depending-on-the-phase-of-the-moon.



""",
                'inventpassphrase',
                '-1.3',
                VersionOutputData(
                    derivation_schemes={
                        'nonsense': True,
                        'divination': False,
                        '/dev/random': False,
                        'geiger counter': False,
                        'crossword solver': False,
                    },
                    foreign_configuration_formats={
                        'derivepassphrase': True,
                        'nonsense': True,
                        'divination v3.141592': False,
                        '/dev/random': False,
                    },
                    subcommands=frozenset({'delete-all-files', 'dump-core'}),
                    features={
                        'delete-while-open': True,
                        'backups-are-nice-to-have': False,
                    },
                    extras=frozenset({
                        'annoying-popups',
                        'delete-all-files',
                        'dump-core-depending-on-the-phase-of-the-moon',
                    }),
                ),
                id='inventpassphrase',
            ),
        ],
    )
    """Sample data for [`parse_version_output`][]."""
    VALIDATION_FUNCTION_INPUT = pytest.mark.parametrize(
        ['vfunc', 'input'],
        [
            (cli_machinery.validate_occurrence_constraint, 20),
            (cli_machinery.validate_length, 20),
        ],
    )


class TestAllCLI:
    """Tests uniformly for all command-line interfaces."""

    @Parametrize.MASK_PROG_NAME
    @Parametrize.MASK_VERSION
    @Parametrize.VERSION_OUTPUT_DATA
    def test_001_parse_version_output(
        self,
        version_output: str,
        prog_name: str | None,
        version: str | None,
        mask_prog_name: bool,
        mask_version: bool,
        expected_parse: VersionOutputData,
    ) -> None:
        """The parsing machinery for expected version output data works."""
        prog_name = None if mask_prog_name else prog_name
        version = None if mask_version else version
        assert (
            parse_version_output(
                version_output, prog_name=prog_name, version=version
            )
            == expected_parse
        )

    # TODO(the-13th-letter): Do we actually need this?  What should we
    # check for?
    def test_100_help_output(self) -> None:
        """The top-level help text mentions subcommands.

        TODO: Do we actually need this?  What should we check for?

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase, ['--help'], catch_exceptions=False
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export', '--help'],
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export', 'vault', '--help'],
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['vault', '--help'],
                catch_exceptions=False,
            )
        assert result.clean_exit(
            empty_stderr=True, output='Passphrase generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use $VISUAL or $EDITOR to configure'
        ), 'expected clean exit, and option group epilog in help text'

    @Parametrize.COMMAND_NON_EAGER_ARGUMENTS
    @Parametrize.EAGER_ARGUMENTS
    def test_200_eager_options(
        self,
        command: list[str],
        arguments: list[str],
        non_eager_arguments: list[str],
    ) -> None:
        """Eager options terminate option and argument processing."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                [*command, *arguments, *non_eager_arguments],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    @Parametrize.NO_COLOR
    @Parametrize.FORCE_COLOR
    @Parametrize.ISATTY
    @Parametrize.COLORFUL_COMMAND_INPUT
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                command_line,
                input=input,
                catch_exceptions=False,
                color=isatty,
            )
        assert (
            not color
            or '\x1b[0m' in result.stderr
            or '\x1b[m' in result.stderr
        ), 'Expected color, but found no ANSI reset sequence'
        assert color or '\x1b[' not in result.stderr, (
            'Expected no color, but found an ANSI control sequence'
        )

    def test_202a_derivepassphrase_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        top-level `derivepassphrase` command, the output should contain
        the known and supported derivation schemes, and a list of
        subcommands.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['--version'],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert result.stdout.strip(), 'expected version output'
        version_data = parse_version_output(result.stdout)
        actually_known_schemes = dict.fromkeys(_types.DerivationScheme, True)
        subcommands = set(_types.Subcommand)
        assert version_data.derivation_schemes == actually_known_schemes
        assert not version_data.foreign_configuration_formats
        assert version_data.subcommands == subcommands
        assert not version_data.features
        assert not version_data.extras

    def test_202b_export_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        `export` command, the output should contain the known foreign
        configuration formats (but not marked as supported), and a list
        of subcommands.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export', '--version'],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert result.stdout.strip(), 'expected version output'
        version_data = parse_version_output(result.stdout)
        actually_known_formats: dict[str, bool] = {
            _types.ForeignConfigurationFormat.VAULT_STOREROOM: False,
            _types.ForeignConfigurationFormat.VAULT_V02: False,
            _types.ForeignConfigurationFormat.VAULT_V03: False,
        }
        subcommands = set(_types.ExportSubcommand)
        assert not version_data.derivation_schemes
        assert (
            version_data.foreign_configuration_formats
            == actually_known_formats
        )
        assert version_data.subcommands == subcommands
        assert not version_data.features
        assert not version_data.extras

    def test_202c_export_vault_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        `export vault` subcommand, the output should contain the
        vault-specific subset of the known or supported foreign
        configuration formats, and a list of available PEP 508 extras.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export', 'vault', '--version'],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert result.stdout.strip(), 'expected version output'
        version_data = parse_version_output(result.stdout)
        actually_known_formats: dict[str, bool] = {}
        actually_enabled_extras: set[str] = set()
        with contextlib.suppress(ModuleNotFoundError):
            from derivepassphrase.exporter import storeroom, vault_native  # noqa: I001,PLC0415

            actually_known_formats.update({
                _types.ForeignConfigurationFormat.VAULT_STOREROOM: not storeroom.STUBBED,
                _types.ForeignConfigurationFormat.VAULT_V02: not vault_native.STUBBED,
                _types.ForeignConfigurationFormat.VAULT_V03: not vault_native.STUBBED,
            })
            if not storeroom.STUBBED and not vault_native.STUBBED:
                actually_enabled_extras.add(_types.PEP508Extra.EXPORT)
        assert not version_data.derivation_schemes
        assert (
            version_data.foreign_configuration_formats
            == actually_known_formats
        )
        assert not version_data.subcommands
        assert not version_data.features
        assert version_data.extras == actually_enabled_extras

    def test_202d_vault_version_option_output(
        self,
    ) -> None:
        """The version output states supported features.

        The version output is parsed using [`parse_version_output`][].
        Format examples can be found in
        [`Parametrize.VERSION_OUTPUT_DATA`][].  Specifically, for the
        vault command, the output should not contain anything beyond the
        first paragraph.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['vault', '--version'],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'
        assert result.stdout.strip(), 'expected version output'
        version_data = parse_version_output(result.stdout)
        features: dict[str, bool] = {
            _types.Feature.SSH_KEY: hasattr(socket, 'AF_UNIX'),
        }
        assert not version_data.derivation_schemes
        assert not version_data.foreign_configuration_formats
        assert not version_data.subcommands
        assert version_data.features == features
        assert not version_data.extras


class TestCLI:
    """Tests for the `derivepassphrase vault` command-line interface."""

    def test_200_help_output(
        self,
    ) -> None:
        """The `--help` option emits help text."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--help'],
                catch_exceptions=False,
            )
        assert result.clean_exit(
            empty_stderr=True, output='Passphrase generation:\n'
        ), 'expected clean exit, and option groups in help text'
        assert result.clean_exit(
            empty_stderr=True, output='Use $VISUAL or $EDITOR to configure'
        ), 'expected clean exit, and option group epilog in help text'

    # TODO(the-13th-letter): Remove this test once
    # TestAllCLI.test_202_version_option_output no longer xfails.
    def test_200a_version_output(
        self,
    ) -> None:
        """The `--version` option emits version information."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--version'],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True, output=cli.PROG_NAME), (
            'expected clean exit, and program name in version text'
        )
        assert result.clean_exit(empty_stderr=True, output=cli.VERSION), (
            'expected clean exit, and version in help text'
        )

    @Parametrize.CHARSET_NAME
    def test_201_disable_character_set(
        self,
        charset_name: str,
    ) -> None:
        """Named character classes can be disabled on the command-line."""
        option = f'--{charset_name}'
        charset = vault.Vault.CHARSETS[charset_name].decode('ascii')
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [option, '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit:'
        for c in charset:
            assert c not in result.stdout, (
                f'derived password contains forbidden character {c!r}'
            )

    def test_202_disable_repetition(
        self,
    ) -> None:
        """Character repetition can be disabled on the command-line."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--repeat', '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), (
            'expected clean exit and empty stderr'
        )
        passphrase = result.stdout.rstrip('\r\n')
        for i in range(len(passphrase) - 1):
            assert passphrase[i : i + 1] != passphrase[i + 1 : i + 2], (
                f'derived password contains repeated character '
                f'at position {i}: {result.stdout!r}'
            )

    @Parametrize.CONFIG_WITH_KEY
    def test_204a_key_from_config(
        self,
        config: _types.VaultConfig,
    ) -> None:
        """A stored configured SSH key will be used."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), (
            'expected clean exit and empty stderr'
        )
        assert result.stdout
        assert (
            result.stdout.rstrip('\n').encode('UTF-8')
            != DUMMY_RESULT_PASSPHRASE
        ), 'known false output: phrase-based instead of key-based'
        assert (
            result.stdout.rstrip('\n').encode('UTF-8') == DUMMY_RESULT_KEY1
        ), 'expected known output'

    def test_204b_key_from_command_line(
        self,
    ) -> None:
        """An SSH key requested on the command-line will be used."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['-k', '--', DUMMY_SERVICE],
                input='1\n',
                catch_exceptions=False,
            )
        assert result.clean_exit(), 'expected clean exit'
        assert result.stdout, 'expected program output'
        last_line = result.stdout.splitlines(True)[-1]
        assert (
            last_line.rstrip('\n').encode('UTF-8') != DUMMY_RESULT_PASSPHRASE
        ), 'known false output: phrase-based instead of key-based'
        assert last_line.rstrip('\n').encode('UTF-8') == DUMMY_RESULT_KEY1, (
            'expected known output'
        )

    @Parametrize.BASE_CONFIG_WITH_KEY_VARIATIONS
    @Parametrize.KEY_INDEX
    def test_204c_key_override_on_command_line(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        config: dict[str, Any],
        key_index: int,
    ) -> None:
        """A command-line SSH key will override the configured key."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['-k', '--', DUMMY_SERVICE],
                input=f'{key_index}\n',
            )
        assert result.clean_exit(), 'expected clean exit'
        assert result.stdout, 'expected program output'
        assert result.stderr, 'expected stderr'
        assert 'Error:' not in result.stderr, (
            'expected no error messages on stderr'
        )

    def test_205_service_phrase_if_key_in_global_config(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """A command-line passphrase will override the configured key."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.clean_exit(), 'expected clean exit'
        assert result.stdout, 'expected program output'
        last_line = result.stdout.splitlines(True)[-1]
        assert (
            last_line.rstrip('\n').encode('UTF-8') != DUMMY_RESULT_PASSPHRASE
        ), 'known false output: phrase-based instead of key-based'
        assert last_line.rstrip('\n').encode('UTF-8') == DUMMY_RESULT_KEY1, (
            'expected known output'
        )

    @Parametrize.KEY_OVERRIDING_IN_CONFIG
    def test_206_setting_phrase_thus_overriding_key_in_config(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
        caplog: pytest.LogCaptureFixture,
        config: _types.VaultConfig,
        command_line: list[str],
    ) -> None:
        """Configuring a passphrase atop an SSH key works, but warns."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(), 'expected clean exit'
        assert not result.stdout.strip(), 'expected no program output'
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

    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32,
                max_codepoint=126,
                include_characters='\n',
            ),
            max_size=256,
        ),
    )
    def test_207_service_with_notes_actually_prints_notes(
        self,
        notes: str,
    ) -> None:
        """Service notes are printed, if they exist."""
        hypothesis.assume('Error:' not in notes)
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {
                            'phrase': DUMMY_PASSPHRASE,
                        },
                        'services': {
                            DUMMY_SERVICE: {
                                'notes': notes,
                                **DUMMY_CONFIG_SETTINGS,
                            },
                        },
                    },
                )
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
            )
        assert result.clean_exit(), 'expected clean exit'
        assert result.stdout, 'expected program output'
        assert result.stdout.strip() == DUMMY_RESULT_PASSPHRASE.decode(
            'ascii'
        ), 'expected known program output'
        assert result.stderr or not notes.strip(), 'expected stderr'
        assert 'Error:' not in result.stderr, (
            'expected no error messages on stderr'
        )
        assert result.stderr.strip() == notes.strip(), (
            'expected known stderr contents'
        )

    @Parametrize.VAULT_CHARSET_OPTION
    def test_210_invalid_argument_range(
        self,
        option: str,
    ) -> None:
        """Requesting invalidly many characters from a class fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [option, value, '-p', '--', DUMMY_SERVICE],
                    input=DUMMY_PASSPHRASE,
                    catch_exceptions=False,
                )
                assert result.error_exit(error='Invalid value'), (
                    'expected error exit and known error message'
                )

    @Parametrize.OPTION_COMBINATIONS_SERVICE_NEEDED
    def test_211_service_needed(
        self,
        options: list[str],
        service: bool | None,
        input: str | None,
        check_success: bool,
    ) -> None:
        """We require or forbid a service argument, depending on options."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                options if service else [*options, '--', DUMMY_SERVICE],
                input=input,
                catch_exceptions=False,
            )
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
                        vault_config={
                            'global': {'phrase': 'abc'},
                            'services': {},
                        },
                    )
                )
                monkeypatch.setattr(
                    cli_helpers, 'prompt_for_passphrase', tests.auto_prompt
                )
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    [*options, '--', DUMMY_SERVICE] if service else options,
                    input=input,
                    catch_exceptions=False,
                )
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

        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=30', '--', ''],
                catch_exceptions=False,
            )
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps({'services': {'': {'length': 40}}}),
                catch_exceptions=False,
            )
            assert result.clean_exit(empty_stderr=False), 'expected clean exit'
            assert result.stderr is not None, 'expected known error output'
            assert all(map(is_expected_warning, caplog.record_tuples)), (
                'expected known error output'
            )
            assert cli_helpers.load_config() == {
                'global': {'length': 30},
                'services': {'': {'length': 40}},
            }, 'requested configuration change was not applied'

    @Parametrize.OPTION_COMBINATIONS_INCOMPATIBLE
    def test_212_incompatible_options(
        self,
        options: list[str],
        service: bool | None,
    ) -> None:
        """Incompatible options are detected."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [*options, '--', DUMMY_SERVICE] if service else options,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.error_exit(error='mutually exclusive with '), (
            'expected error exit and known error message'
        )

    @Parametrize.VALID_TEST_CONFIGS
    def test_213_import_config_success(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Importing a configuration works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            config_txt = cli_helpers.config_filename(
                subsystem='vault'
            ).read_text(encoding='UTF-8')
            config2 = json.loads(config_txt)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config2 == config, 'config not imported correctly'
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'
        assert_vault_config_is_indented_and_line_broken(config_txt)

    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
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
        # Reset caplog between hypothesis runs.
        caplog.clear()
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input=json.dumps(config),
                catch_exceptions=False,
            )
            config_txt = cli_helpers.config_filename(
                subsystem='vault'
            ).read_text(encoding='UTF-8')
            config3 = json.loads(config_txt)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config3 == config2, 'config not imported correctly'
        assert not result.stderr or all(
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'
        assert_vault_config_is_indented_and_line_broken(config_txt)

    def test_213b_import_bad_config_not_vault_config(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='null',
                catch_exceptions=False,
            )
        assert result.error_exit(error='Invalid vault config'), (
            'expected error exit and known error message'
        )

    def test_213c_import_bad_config_not_json_data(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', '-'],
                input='This string is not valid JSON.',
                catch_exceptions=False,
            )
        assert result.error_exit(error='cannot decode JSON'), (
            'expected error exit and known error message'
        )

    def test_213d_import_bad_config_not_a_file(
        self,
    ) -> None:
        """Importing an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--import', os.fsdecode(dname)],
                catch_exceptions=False,
            )
        assert result.error_exit(error=os.strerror(errno.EISDIR)), (
            'expected error exit and known error message'
        )

    @Parametrize.VALID_TEST_CONFIGS
    def test_214_export_config_success(
        self,
        caplog: pytest.LogCaptureFixture,
        config: Any,
    ) -> None:
        """Exporting a configuration works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            with cli_helpers.config_filename(subsystem='vault').open(
                'w', encoding='UTF-8'
            ) as outfile:
                # Ensure the config is written on one line.
                json.dump(config, outfile, indent=None)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config2 = json.load(infile)
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert config2 == config, 'config not imported correctly'
        assert not result.stderr or all(  # pragma: no branch
            map(is_harmless_config_import_warning, caplog.record_tuples)
        ), 'unexpected error output'
        assert_vault_config_is_indented_and_line_broken(result.stdout)

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_214a_export_settings_no_stored_settings(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting the default, empty config works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(subsystem='vault').unlink(
                missing_ok=True
            )
            result = runner.invoke(
                # Test parent context navigation by not calling
                # `cli.derivepassphrase_vault` directly.  Used e.g. in
                # the `--export-as=sh` section to autoconstruct the
                # program name correctly.
                cli.derivepassphrase,
                ['vault', '--export', '-', *export_options],
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=True), 'expected clean exit'

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_214b_export_settings_bad_stored_config(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot load vault settings:'), (
            'expected error exit and known error message'
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_214c_export_settings_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot load vault settings:'), (
            'expected error exit and known error message'
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_214d_export_settings_target_not_a_file(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', os.fsdecode(dname), *export_options],
                input='null',
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot export vault settings:'), (
            'expected error exit and known error message'
        )

    @Parametrize.EXPORT_FORMAT_OPTIONS
    def test_214e_export_settings_settings_directory_not_a_directory(
        self,
        export_options: list[str],
    ) -> None:
        """Exporting an invalid config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-', *export_options],
                input='null',
                catch_exceptions=False,
            )
        assert result.error_exit(
            error='Cannot load vault settings:'
        ) or result.error_exit(error='Cannot load user config:'), (
            'expected error exit and known error message'
        )

    @Parametrize.NOTES_PLACEMENT
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_215_notes_placement(
        self,
        notes_placement: Literal['before', 'after'],
        placement_args: list[str],
        notes: str,
    ) -> None:
        notes = notes.strip()
        maybe_notes = {'notes': notes} if notes else {}
        vault_config = {
            'global': {'phrase': DUMMY_PASSPHRASE},
            'services': {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        result_phrase = DUMMY_RESULT_PASSPHRASE.decode('ascii')
        expected = (
            f'{notes}\n\n{result_phrase}\n'
            if notes_placement == 'before'
            else f'{result_phrase}\n\n{notes}\n\n'
        )
        runner = tests.CliRunner(mix_stderr=True)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [*placement_args, '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
            assert result.clean_exit(output=expected), 'expected clean exit'

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_220_edit_notes_successfully(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes works."""
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = f"""

{marker}
{notes}
"""
        # Reset caplog between hypothesis runs.
        caplog.clear()
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {'phrase': 'abc'},
                        'services': {'sv': {'notes': 'Contents go here'}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem='notes backup'
            )
            notes_backup_file.write_text(
                'These backup notes are left over from the previous session.',
                encoding='UTF-8',
            )
            monkeypatch.setattr(click, 'edit', lambda *_a, **_kw: edit_result)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--notes',
                    '--modern-editor-interface'
                    if modern_editor_interface
                    else '--vault-legacy-editor-interface',
                    '--',
                    'sv',
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(), 'expected clean exit'
            assert all(map(is_warning_line, result.stderr.splitlines(True)))
            assert modern_editor_interface or tests.warning_emitted(
                'A backup copy of the old notes was saved',
                caplog.record_tuples,
            ), 'expected known warning message in stderr'
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding='UTF-8')
                == 'Contents go here'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {
                    'sv': {
                        'notes': notes.strip()
                        if modern_editor_interface
                        else edit_result.strip()
                    }
                },
            }

    @Parametrize.NOOP_EDIT_FUNCS
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_221_edit_notes_noop(
        self,
        edit_func_name: Literal['empty', 'space'],
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Abandoning edited notes works."""

        def empty(text: str, *_args: Any, **_kwargs: Any) -> str:
            del text
            return ''

        def space(text: str, *_args: Any, **_kwargs: Any) -> str:
            del text
            return '       ' + notes.strip() + '\n\n\n\n\n\n'

        edit_funcs = {'empty': empty, 'space': space}
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {'phrase': 'abc'},
                        'services': {'sv': {'notes': notes.strip()}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem='notes backup'
            )
            notes_backup_file.write_text(
                'These backup notes are left over from the previous session.',
                encoding='UTF-8',
            )
            monkeypatch.setattr(click, 'edit', edit_funcs[edit_func_name])
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--notes',
                    '--modern-editor-interface'
                    if modern_editor_interface
                    else '--vault-legacy-editor-interface',
                    '--',
                    'sv',
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(empty_stderr=True) or result.error_exit(
                error='the user aborted the request'
            ), 'expected clean exit'
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding='UTF-8')
                == 'These backup notes are left over from the previous session.'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': notes.strip()}},
            }

    # TODO(the-13th-letter): Keep this behavior or not, with or without
    # warning?
    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_222_edit_notes_marker_removed(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Removing the notes marker still saves the notes.

        TODO: Keep this behavior or not, with or without warning?

        """
        notes_marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        hypothesis.assume(str(notes_marker) not in notes.strip())
        # Reset caplog between hypothesis runs.
        caplog.clear()
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {'phrase': 'abc'},
                        'services': {'sv': {'notes': 'Contents go here'}},
                    },
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem='notes backup'
            )
            notes_backup_file.write_text(
                'These backup notes are left over from the previous session.',
                encoding='UTF-8',
            )
            monkeypatch.setattr(click, 'edit', lambda *_a, **_kw: notes)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--notes',
                    '--modern-editor-interface'
                    if modern_editor_interface
                    else '--vault-legacy-editor-interface',
                    '--',
                    'sv',
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(), 'expected clean exit'
            assert not result.stderr or all(
                map(is_warning_line, result.stderr.splitlines(True))
            )
            assert not caplog.record_tuples or tests.warning_emitted(
                'A backup copy of the old notes was saved',
                caplog.record_tuples,
            ), 'expected known warning message in stderr'
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding='UTF-8')
                == 'Contents go here'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': notes.strip()}},
            }

    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            min_size=1,
            max_size=512,
        ).filter(str.strip),
    )
    def test_223_edit_notes_abort(
        self,
        notes: str,
    ) -> None:
        """Aborting editing notes works.

        Aborting is only supported with the modern editor interface.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {'phrase': 'abc'},
                        'services': {'sv': {'notes': notes.strip()}},
                    },
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *_a, **_kw: '')
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--notes',
                    '--modern-editor-interface',
                    '--',
                    'sv',
                ],
                catch_exceptions=False,
            )
            assert result.error_exit(error='the user aborted the request'), (
                'expected known error message'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {'sv': {'notes': notes.strip()}},
            }

    def test_223a_edit_empty_notes_abort(
        self,
    ) -> None:
        """Aborting editing notes works even if no notes are stored yet.

        Aborting is only supported with the modern editor interface.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
                        'global': {'phrase': 'abc'},
                        'services': {},
                    },
                )
            )
            monkeypatch.setattr(click, 'edit', lambda *_a, **_kw: '')
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--config',
                    '--notes',
                    '--modern-editor-interface',
                    '--',
                    'sv',
                ],
                catch_exceptions=False,
            )
            assert result.error_exit(error='the user aborted the request'), (
                'expected known error message'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == {
                'global': {'phrase': 'abc'},
                'services': {},
            }

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters='\n'
            ),
            max_size=512,
        ),
    )
    def test_223b_edit_notes_fail_config_option_missing(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes fails (and warns) if `--config` is missing."""
        maybe_notes = {'notes': notes.strip()} if notes.strip() else {}
        vault_config = {
            'global': {'phrase': DUMMY_PASSPHRASE},
            'services': {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        # Reset caplog between hypothesis runs.
        caplog.clear()
        runner = tests.CliRunner(mix_stderr=False)
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
            EDIT_ATTEMPTED = 'edit attempted!'  # noqa: N806

            def raiser(*_args: Any, **_kwargs: Any) -> NoReturn:
                pytest.fail(EDIT_ATTEMPTED)

            notes_backup_file = cli_helpers.config_filename(
                subsystem='notes backup'
            )
            notes_backup_file.write_text(
                'These backup notes are left over from the previous session.',
                encoding='UTF-8',
            )
            monkeypatch.setattr(click, 'edit', raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    '--notes',
                    '--modern-editor-interface'
                    if modern_editor_interface
                    else '--vault-legacy-editor-interface',
                    '--',
                    DUMMY_SERVICE,
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(
                output=DUMMY_RESULT_PASSPHRASE.decode('ascii')
            ), 'expected clean exit'
            assert result.stderr
            assert notes.strip() in result.stderr
            assert all(
                is_warning_line(line)
                for line in result.stderr.splitlines(True)
                if line.startswith(f'{cli.PROG_NAME}: ')
            )
            assert tests.warning_emitted(
                'Specifying --notes without --config is ineffective.  '
                'No notes will be edited.',
                caplog.record_tuples,
            ), 'expected known warning message in stderr'
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding='UTF-8')
                == 'These backup notes are left over from the previous session.'
            )
            with cli_helpers.config_filename(subsystem='vault').open(
                encoding='UTF-8'
            ) as infile:
                config = json.load(infile)
            assert config == vault_config

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG
    def test_224_store_config_good(
        self,
        command_line: list[str],
        input: str,
        result_config: Any,
    ) -> None:
        """Storing valid settings via `--config` works.

        The format also contains embedded newlines and indentation to make
        the config more readable.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
            assert result.clean_exit(), 'expected clean exit'
            config_txt = cli_helpers.config_filename(
                subsystem='vault'
            ).read_text(encoding='UTF-8')
            config = json.loads(config_txt)
            assert config == result_config, (
                'stored config does not match expectation'
            )
            assert_vault_config_is_indented_and_line_broken(config_txt)

    @Parametrize.CONFIG_EDITING_VIA_CONFIG_FLAG_FAILURES
    def test_225_store_config_fail(
        self,
        command_line: list[str],
        input: str,
        err_text: str,
    ) -> None:
        """Storing invalid settings via `--config` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', *command_line],
                catch_exceptions=False,
                input=input,
            )
        assert result.error_exit(error=err_text), (
            'expected error exit and known error message'
        )

    def test_225a_store_config_fail_manual_no_ssh_key_selection(
        self,
    ) -> None:
        """Not selecting an SSH key during `--config --key` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(error=custom_error), (
            'expected error exit and known error message'
        )

    def test_225b_store_config_fail_manual_no_ssh_agent(
        self,
        skip_if_no_af_unix_support: None,
    ) -> None:
        """Not running an SSH agent during `--config --key` fails."""
        del skip_if_no_af_unix_support
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot find any running SSH agent'), (
            'expected error exit and known error message'
        )

    def test_225c_store_config_fail_manual_bad_ssh_agent_connection(
        self,
    ) -> None:
        """Not running a reachable SSH agent during `--config --key` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot connect to the SSH agent'), (
            'expected error exit and known error message'
        )

    @Parametrize.TRY_RACE_FREE_IMPLEMENTATION
    def test_225d_store_config_fail_manual_read_only_file(
        self,
        try_race_free_implementation: bool,
    ) -> None:
        """Using a read-only configuration file with `--config` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(error='Cannot store vault settings:'), (
            'expected error exit and known error message'
        )

    def test_225e_store_config_fail_manual_custom_error(
        self,
    ) -> None:
        """OS-erroring with `--config` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '--length=15', '--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
        assert result.error_exit(error=custom_error), (
            'expected error exit and known error message'
        )

    def test_225f_store_config_fail_unset_and_set_same_settings(
        self,
    ) -> None:
        """Issuing conflicting settings to `--config` fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
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
        assert result.error_exit(
            error='Attempted to unset and set --length at the same time.'
        ), 'expected error exit and known error message'

    def test_225g_store_config_fail_manual_ssh_agent_no_keys_loaded(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """Not holding any SSH keys during `--config --key` fails."""
        del running_ssh_agent
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(error='no keys suitable'), (
            'expected error exit and known error message'
        )

    def test_225h_store_config_fail_manual_ssh_agent_runtime_error(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """The SSH agent erroring during `--config --key` fails."""
        del running_ssh_agent
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error='violates the communication protocol.'
        ), 'expected error exit and known error message'

    def test_225i_store_config_fail_manual_ssh_agent_refuses(
        self,
        running_ssh_agent: tests.RunningSSHAgentInfo,
    ) -> None:
        """The SSH agent refusing during `--config --key` fails."""
        del running_ssh_agent
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(error='refused to'), (
            'expected error exit and known error message'
        )

    def test_226_no_arguments(self) -> None:
        """Calling `derivepassphrase vault` without any arguments fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault, [], catch_exceptions=False
            )
        assert result.error_exit(
            error='Deriving a passphrase requires a SERVICE'
        ), 'expected error exit and known error message'

    def test_226a_no_passphrase_or_key(
        self,
    ) -> None:
        """Deriving a passphrase without a passphrase or key fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--', DUMMY_SERVICE],
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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

            monkeypatch.setattr(
                cli_helpers, 'save_config', obstruct_config_saving
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            assert result.error_exit(error='Cannot store vault settings:'), (
                'expected error exit and known error message'
            )

    def test_230b_store_config_custom_error(
        self,
    ) -> None:
        """Storing the configuration reacts even to weird errors."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--config', '-p'],
                catch_exceptions=False,
                input='abc\n',
            )
            assert result.error_exit(error=custom_error), (
                'expected error exit and known error message'
            )

    @Parametrize.UNICODE_NORMALIZATION_WARNING_INPUTS
    def test_300_unicode_normalization_form_warning(
        self,
        caplog: pytest.LogCaptureFixture,
        main_config: str,
        command_line: list[str],
        input: str | None,
        warning_message: str,
    ) -> None:
        """Using unnormalized Unicode passphrases warns."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--debug', *command_line],
                catch_exceptions=False,
                input=input,
            )
        assert result.clean_exit(), 'expected clean exit'
        assert tests.warning_emitted(warning_message, caplog.record_tuples), (
            'expected known warning message in stderr'
        )

    @Parametrize.UNICODE_NORMALIZATION_ERROR_INPUTS
    def test_301_unicode_normalization_form_error(
        self,
        main_config: str,
        command_line: list[str],
        input: str | None,
        error_message: str,
    ) -> None:
        """Using unknown Unicode normalization forms fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                catch_exceptions=False,
                input=input,
            )
        assert result.error_exit(
            error='The user configuration file is invalid.'
        ), 'expected error exit and known error message'
        assert result.error_exit(error=error_message), (
            'expected error exit and known error message'
        )

    @Parametrize.UNICODE_NORMALIZATION_COMMAND_LINES
    def test_301a_unicode_normalization_form_error_from_stored_config(
        self,
        command_line: list[str],
    ) -> None:
        """Using unknown Unicode normalization forms in the config fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                command_line,
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--phrase', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(error='Cannot load user config:'), (
                'expected error exit and known error message'
            )

    def test_311_bad_user_config_is_a_directory(
        self,
    ) -> None:
        """Loading a user configuration file in an invalid format fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
                    main_config_str='',
                )
            )
            user_config = cli_helpers.config_filename(
                subsystem='user configuration'
            )
            user_config.unlink()
            user_config.mkdir(parents=True, exist_ok=True)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--phrase', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
            assert result.error_exit(error='Cannot load user config:'), (
                'expected error exit and known error message'
            )

    def test_400_missing_af_unix_support(
        self,
    ) -> None:
        """Querying the SSH agent without `AF_UNIX` support fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--key', '--config'],
                catch_exceptions=False,
            )
        assert result.error_exit(
            error='does not support UNIX domain sockets'
        ), 'expected error exit and known error message'


class TestCLIUtils:
    """Tests for command-line utility functions."""

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_100_load_config(
        self,
        config: Any,
    ) -> None:
        """[`cli_helpers.load_config`][] works for valid configurations."""
        runner = tests.CliRunner(mix_stderr=False)
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
        runner = tests.CliRunner(mix_stderr=False)
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

        runner = tests.CliRunner(mix_stderr=True)
        result = runner.invoke(driver, [], input='9')
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
        result = runner.invoke(
            driver, ['--heading='], input='', catch_exceptions=True
        )
        assert result.error_exit(error=IndexError), (
            'expected error exit and known error type'
        )
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

        runner = tests.CliRunner(mix_stderr=True)
        result = runner.invoke(
            driver, ['Will replace with spam. Confirm, y/n?'], input='y'
        )
        assert result.clean_exit(
            output="""\
[1] baked beans
Will replace with spam. Confirm, y/n? y
Great!
"""
        ), 'expected clean exit'
        result = runner.invoke(
            driver,
            ['Will replace with spam, okay? (Please say "y" or "n".)'],
            input='',
        )
        assert result.error_exit(error=IndexError), (
            'expected error exit and known error type'
        )
        assert (
            result.stdout
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
        warnings_cm = (
            cli_machinery.StandardCLILogging.ensure_standard_warnings_logging()
        )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            for result in vault_config_exporter_shell_interpreter(script):
                assert result.clean_exit()
            assert cli_helpers.load_config() == config

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

    @hypothesis.given(
        env_var=strategies.sampled_from(['TMPDIR', 'TEMP', 'TMP']),
        suffix=strategies.text(
            tuple(' 0123456789abcdefghijklmnopqrstuvwxyz'),
            min_size=12,
            max_size=12,
        ),
    )
    @hypothesis.example(env_var='', suffix='.')
    def test_140a_get_tempdir(
        self,
        env_var: str,
        suffix: str,
    ) -> None:
        """[`cli_helpers.get_tempdir`][] returns a temporary directory.

        If it is not the same as the temporary directory determined by
        [`tempfile.gettempdir`][], then assert that
        `tempfile.gettempdir` returned the current directory and
        `cli_helpers.get_tempdir` returned the configuration directory.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            monkeypatch.delenv('TMPDIR', raising=False)
            monkeypatch.delenv('TEMP', raising=False)
            monkeypatch.delenv('TMP', raising=False)
            if env_var:
                monkeypatch.setenv(env_var, str(pathlib.Path.cwd() / suffix))
            system_tempdir = os.fsdecode(tempfile.gettempdir())
            our_tempdir = cli_helpers.get_tempdir()
            assert system_tempdir == os.fsdecode(our_tempdir) or (
                # TODO(the-13th-letter): `tests.isolated_config`
                # guarantees that `Path.cwd() == config_filename(None)`.
                # So this sub-branch ought to never trigger in our
                # tests.
                system_tempdir == os.getcwd()  # noqa: PTH109
                and our_tempdir == cli_helpers.config_filename(subsystem=None)
            )

    def test_140b_get_tempdir_force_default(self) -> None:
        """[`cli_helpers.get_tempdir`][] returns a temporary directory.

        If all candidates are mocked to fail for the standard temporary
        directory choices, then we return the `derivepassphrase`
        configuration directory.

        """
        runner = tests.CliRunner(mix_stderr=False)
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
            monkeypatch.delenv('TMPDIR', raising=False)
            monkeypatch.delenv('TEMP', raising=False)
            monkeypatch.delenv('TMP', raising=False)
            config_dir = cli_helpers.config_filename(subsystem=None)

            def is_dir_false(
                self: pathlib.Path,
                /,
                *,
                follow_symlinks: bool = False,
            ) -> bool:
                del self, follow_symlinks
                return False

            def is_dir_error(
                self: pathlib.Path,
                /,
                *,
                follow_symlinks: bool = False,
            ) -> bool:
                del follow_symlinks
                raise OSError(
                    errno.EACCES,
                    os.strerror(errno.EACCES),
                    str(self),
                )

            monkeypatch.setattr(pathlib.Path, 'is_dir', is_dir_false)
            assert cli_helpers.get_tempdir() == config_dir

            monkeypatch.setattr(pathlib.Path, 'is_dir', is_dir_error)
            assert cli_helpers.get_tempdir() == config_dir

    @Parametrize.DELETE_CONFIG_INPUT
    def test_203_repeated_config_deletion(
        self,
        command_line: list[str],
        config: _types.VaultConfig,
        result_config: _types.VaultConfig,
    ) -> None:
        """Repeatedly removing the same parts of a configuration works."""
        for start_config in [config, result_config]:
            runner = tests.CliRunner(mix_stderr=False)
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
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    command_line,
                    catch_exceptions=False,
                )
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

    @Parametrize.VALIDATION_FUNCTION_INPUT
    def test_210a_validate_constraints_manually(
        self,
        vfunc: Callable[[click.Context, click.Parameter, Any], int | None],
        input: int,
    ) -> None:
        """Command-line argument constraint validation works."""
        ctx = cli.derivepassphrase_vault.make_context(cli.PROG_NAME, [])
        param = cli.derivepassphrase_vault.params[0]
        assert vfunc(ctx, param, input) == input

    @Parametrize.CONNECTION_HINTS
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
                    ErrCallback, match='violates the communication protocol'
                ):
                    cli_helpers.key_to_phrase(loaded_key, error_callback=err)


# TODO(the-13th-letter): Remove this class in v1.0.
# https://the13thletter.info/derivepassphrase/latest/upgrade-notes/#upgrading-to-v1.0
class TestCLITransition:
    """Transition tests for the command-line interface up to v1.0."""

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_110_load_config_backup(
        self,
        config: Any,
    ) -> None:
        """Loading the old settings file works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(json.dumps(config, indent=2) + '\n', encoding='UTF-8')
            assert cli_helpers.migrate_and_load_old_config()[0] == config

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_111_migrate_config(
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(json.dumps(config, indent=2) + '\n', encoding='UTF-8')
            assert cli_helpers.migrate_and_load_old_config() == (config, None)

    @Parametrize.BASE_CONFIG_VARIATIONS
    def test_112_migrate_config_error(
        self,
        config: Any,
    ) -> None:
        """Migrating the old settings file atop a directory fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(json.dumps(config, indent=2) + '\n', encoding='UTF-8')
            cli_helpers.config_filename(subsystem='vault').mkdir(
                parents=True, exist_ok=True
            )
            config2, err = cli_helpers.migrate_and_load_old_config()
            assert config2 == config
            assert isinstance(err, OSError)
            assert err.errno == errno.EISDIR

    @Parametrize.BAD_CONFIGS
    def test_113_migrate_config_error_bad_config_value(
        self,
        config: Any,
    ) -> None:
        """Migrating an invalid old settings file fails."""
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(json.dumps(config, indent=2) + '\n', encoding='UTF-8')
            with pytest.raises(
                ValueError, match=cli_helpers.INVALID_VAULT_CONFIG
            ):
                cli_helpers.migrate_and_load_old_config()

    def test_200_forward_export_vault_path_parameter(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Forwarding arguments from "export" to "export vault" works."""
        pytest.importorskip('cryptography', minversion='38.0')
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export', 'VAULT_PATH'],
            )
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert json.loads(result.stdout) == tests.VAULT_V03_CONFIG_DATA

    def test_201_forward_export_vault_empty_commandline(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from "export" to "export vault" works."""
        pytest.importorskip('cryptography', minversion='38.0')
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                ['export'],
            )
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        assert result.error_exit(error="Missing argument 'PATH'"), (
            'expected error exit and known error type'
        )

    @Parametrize.CHARSET_NAME
    def test_210_forward_vault_disable_character_set(
        self,
        caplog: pytest.LogCaptureFixture,
        charset_name: str,
    ) -> None:
        """Forwarding arguments from top-level to "vault" works."""
        option = f'--{charset_name}'
        charset = vault.Vault.CHARSETS[charset_name].decode('ascii')
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                [option, '0', '-p', '--', DUMMY_SERVICE],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
        assert result.clean_exit(empty_stderr=False), 'expected clean exit'
        assert tests.deprecation_warning_emitted(
            'A subcommand will be required here in v1.0', caplog.record_tuples
        )
        assert tests.deprecation_warning_emitted(
            'Defaulting to subcommand "vault"', caplog.record_tuples
        )
        for c in charset:
            assert c not in result.stdout, (
                f'derived password contains forbidden character {c!r}'
            )

    def test_211_forward_vault_empty_command_line(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Deferring from top-level to "vault" works."""
        runner = tests.CliRunner(mix_stderr=False)
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
            result = runner.invoke(
                cli.derivepassphrase,
                [],
                input=DUMMY_PASSPHRASE,
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(
                json.dumps(
                    {'services': {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}},
                    indent=2,
                )
                + '\n',
                encoding='UTF-8',
            )
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(
                subsystem='old settings.json'
            ).write_text(
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                ['--export', '-'],
                catch_exceptions=False,
            )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            old_name = cli_helpers.config_filename(
                subsystem='old settings.json'
            )
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
        self.runner = tests.CliRunner(mix_stderr=False)
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
        result = self.runner.invoke(
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
        result = self.runner.invoke(
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
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete-globals'],
            input='y',
            catch_exceptions=False,
        )
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
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--delete', '--', service],
            input='y',
            catch_exceptions=False,
        )
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
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--clear'],
            input='y',
            catch_exceptions=False,
        )
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
        result = self.runner.invoke(
            cli.derivepassphrase_vault,
            ['--import', '-']
            + (['--overwrite-existing'] if overwrite else []),
            input=json.dumps(config_to_import),
            catch_exceptions=False,
        )
        assert result.clean_exit(empty_stderr=False)
        assert cli_helpers.load_config() == config
        return config

    def teardown(self) -> None:
        """Upon teardown, exit all contexts entered in `__init__`."""
        self.exit_stack.close()


TestConfigManagement = ConfigManagementStateMachine.TestCase
"""The [`unittest.TestCase`][] class that will actually be run."""


class FakeConfigurationMutexAction(NamedTuple):
    """An action/a step in the [`FakeConfigurationMutexStateMachine`][].

    Attributes:
        command_line:
            The command-line for `derivepassphrase vault` to execute.
        input:
            The input to this command.

    """

    command_line: list[str]
    """"""
    input: str | bytes | None = None
    """"""


def run_actions_handler(
    id_num: int,
    action: FakeConfigurationMutexAction,
    *,
    input_queue: queue.Queue,
    output_queue: queue.Queue,
    timeout: int,
) -> None:
    """Prepare the faked mutex, then run `action`.

    This is a top-level handler function -- to be used in a new
    [`multiprocessing.Process`][] -- to run a single action from the
    [`FakeConfigurationMutexStateMachine`][].  Output from this function
    must be sent down the output queue instead of relying on the call
    stack.  Additionally, because this runs in a separate process, we
    need to restart coverage tracking if it is currently running.

    Args:
        id_num:
            The internal ID of this subprocess.
        action:
            The action to execute.
        input_queue:
            The queue for data passed from the manager/parent process to
            this subprocess.
        output_queue:
            The queue for data passed from this subprocess to the
            manager/parent process.
        timeout:
            The maximum amount of time to wait for a data transfer along
            the input or the output queue.  If exceeded, we exit
            immediately.

    """
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            cli_helpers,
            'configuration_mutex',
            lambda: FakeConfigurationMutexStateMachine.ConfigurationMutexStub(
                my_id=id_num,
                input_queue=input_queue,
                output_queue=output_queue,
                timeout=timeout,
            ),
        )
        runner = tests.CliRunner(mix_stderr=False)
        try:
            result = runner.invoke(
                cli.derivepassphrase_vault,
                args=action.command_line,
                input=action.input,
                catch_exceptions=True,
            )
            output_queue.put(
                FakeConfigurationMutexStateMachine.IPCMessage(
                    id_num,
                    'result',
                    (
                        result.clean_exit(empty_stderr=False),
                        copy.copy(result.stdout),
                        copy.copy(result.stderr),
                    ),
                ),
                block=True,
                timeout=timeout,
            )
        except Exception as exc:  # pragma: no cover  # noqa: BLE001
            output_queue.put(
                FakeConfigurationMutexStateMachine.IPCMessage(
                    id_num, 'exception', exc
                ),
                block=False,
            )


@hypothesis.settings(
    stateful_step_count=tests.get_concurrency_step_count(),
    deadline=None,
)
class FakeConfigurationMutexStateMachine(stateful.RuleBasedStateMachine):
    """A state machine simulating the (faked) configuration mutex.

    Generate an ordered set of concurrent writers to the
    derivepassphrase configuration, then test that the writers' accesses
    are serialized correctly, i.e., test that the writers correctly use
    the mutex to avoid concurrent accesses, under the assumption that
    the mutex itself is correctly implemented.

    We use a custom mutex implementation to both ensure that all writers
    attempt to lock the configuration at the same time and that the lock
    is granted in our desired order.  This test is therefore independent
    of the actual (operating system-specific) mutex implementation in
    `derivepassphrase`.

    Attributes:
        setting:
            A bundle for single-service settings.
        configuration:
            A bundle for full vault configurations.

    """

    class IPCMessage(NamedTuple):
        """A message for inter-process communication.

        Used by the configuration mutex stub class to affect/signal the
        control flow amongst the linked mutex clients.

        Attributes:
            child_id:
                The ID of the sending or receiving child process.
            message:
                One of "ready", "go", "config", "result" or "exception".
            payload:
                The (optional) message payload.

        """

        child_id: int
        """"""
        message: Literal['ready', 'go', 'config', 'result', 'exception']
        """"""
        payload: object | None
        """"""

    class ConfigurationMutexStub(cli_helpers.ConfigurationMutex):
        """Configuration mutex subclass that enforces a locking order.

        Each configuration mutex stub object ("mutex client") has an
        associated ID, and one read-only and one write-only pipe
        (actually: [`multiprocessing.Queue`][] objects) to the "manager"
        instance coordinating these stub objects.  First, the mutex
        client signals readiness, then the manager signals when the
        mutex shall be considered "acquired", then finally the mutex
        client sends the result back (simultaneously releasing the mutex
        again).  The manager may optionally send an abort signal if the
        operations take too long.

        This subclass also copies the effective vault configuration
        to `intermediate_configs` upon releasing the lock.

        """

        def __init__(
            self,
            *,
            my_id: int,
            timeout: int,
            input_queue: queue.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ],
            output_queue: queue.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ],
        ) -> None:
            """Initialize this mutex client.

            Args:
                my_id:
                    The ID of this client.
                timeout:
                    The timeout for each get and put operation on the
                    queues.
                input_queue:
                    The message queue for IPC messages from the manager
                    instance to this mutex client.
                output_queue:
                    The message queue for IPC messages from this mutex
                    client to the manager instance.

            """
            super().__init__()

            def lock() -> None:
                """Simulate locking of the mutex.

                Issue a "ready" message, wait for a "go", then return.
                If an exception occurs, issue an "exception" message,
                then raise the exception.

                """
                IPCMessage: TypeAlias = (
                    FakeConfigurationMutexStateMachine.IPCMessage
                )
                try:
                    output_queue.put(
                        IPCMessage(my_id, 'ready', None),
                        block=True,
                        timeout=timeout,
                    )
                    ok = input_queue.get(block=True, timeout=timeout)
                    if ok != IPCMessage(my_id, 'go', None):  # pragma: no cover
                        output_queue.put(
                            IPCMessage(my_id, 'exception', ok), block=False
                        )
                        raise (
                            ok[2]
                            if isinstance(ok[2], BaseException)
                            else RuntimeError(ok[2])
                        )
                except (queue.Empty, queue.Full) as exc:  # pragma: no cover
                    output_queue.put(
                        IPCMessage(my_id, 'exception', exc), block=False
                    )
                    return

            def unlock() -> None:
                """Simulate unlocking of the mutex.

                Issue a "config" message, then return.  If an exception
                occurs, issue an "exception" message, then raise the
                exception.

                """
                IPCMessage: TypeAlias = (
                    FakeConfigurationMutexStateMachine.IPCMessage
                )
                try:
                    output_queue.put(
                        IPCMessage(
                            my_id,
                            'config',
                            copy.copy(cli_helpers.load_config()),
                        ),
                        block=True,
                        timeout=timeout,
                    )
                except (queue.Empty, queue.Full) as exc:  # pragma: no cover
                    output_queue.put(
                        IPCMessage(my_id, 'exception', exc), block=False
                    )
                    raise

            self.lock = lock
            self.unlock = unlock

    setting: stateful.Bundle[_types.VaultConfigServicesSettings] = (
        stateful.Bundle('setting')
    )
    """"""
    configuration: stateful.Bundle[_types.VaultConfig] = stateful.Bundle(
        'configuration'
    )
    """"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the state machine."""
        super().__init__(*args, **kwargs)
        self.actions: list[FakeConfigurationMutexAction] = []
        # Determine the step count by poking around in the hypothesis
        # internals. As this isn't guaranteed to be stable, turn off
        # coverage.
        try:  # pragma: no cover
            settings: hypothesis.settings | None
            settings = FakeConfigurationMutexStateMachine.TestCase.settings
        except AttributeError:  # pragma: no cover
            settings = None
        self.step_count = tests.get_concurrency_step_count(settings)

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
        configs: list[_types.VaultConfig],
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

    @stateful.initialize(
        config=vault_full_config(),
    )
    def declare_initial_action(
        self,
        config: _types.VaultConfig,
    ) -> None:
        """Initialize the actions bundle from the configuration bundle.

        This is roughly comparable to the
        [`add_import_configuration_action`][] general rule, but adding
        it as a separate initialize rule avoids having to guard every
        other action-amending rule against empty action sequences, which
        would discard huge portions of the rule selection search space
        and thus trigger loads of hypothesis health check warnings.

        """
        command_line = ['--import', '-', '--overwrite-existing']
        input = json.dumps(config)  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def add_set_globals_action(
        self,
        setting: _types.VaultConfigGlobalSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> None:
        """Set the global settings of a configuration.

        Args:
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

        """
        maybe_unset = set(maybe_unset) - setting.keys()
        command_line = (
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
        )
        input = None  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        service=strategies.sampled_from(KNOWN_SERVICES),
        setting=setting.filter(bool),
        maybe_unset=strategies.sets(
            strategies.sampled_from(VALID_PROPERTIES),
            max_size=3,
        ),
        overwrite=strategies.booleans(),
    )
    def add_set_service_action(
        self,
        service: str,
        setting: _types.VaultConfigServicesSettings,
        maybe_unset: set[str],
        overwrite: bool,
    ) -> None:
        """Set the named service settings for a configuration.

        Args:
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

        """
        maybe_unset = set(maybe_unset) - setting.keys()
        command_line = (
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
            + ['--', service]
        )
        input = None  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule()
    def add_purge_global_action(
        self,
    ) -> None:
        """Purge the globals of a configuration."""
        command_line = ['--delete-globals']
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        service=strategies.sampled_from(KNOWN_SERVICES),
    )
    def add_purge_service_action(
        self,
        service: str,
    ) -> None:
        """Purge the settings of a named service in a configuration.

        Args:
            service:
                The service name to purge.

        """
        command_line = ['--delete', '--', service]
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule()
    def add_purge_all_action(
        self,
    ) -> None:
        """Purge the entire configuration."""
        command_line = ['--clear']
        input = None  # 'y'  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.rule(
        config_to_import=configuration,
        overwrite=strategies.booleans(),
    )
    def add_import_configuration_action(
        self,
        config_to_import: _types.VaultConfig,
        overwrite: bool,
    ) -> None:
        """Import the given configuration.

        Args:
            config_to_import:
                The configuration to import.
            overwrite:
                Overwrite the base configuration if true, or merge if
                false.  Corresponds to the `--overwrite-existing` and
                `--merge-existing` command-line arguments.

        """
        command_line = ['--import', '-'] + (
            ['--overwrite-existing'] if overwrite else []
        )
        input = json.dumps(config_to_import)  # noqa: A001
        hypothesis.note(f'# {command_line = }, {input = }')
        action = FakeConfigurationMutexAction(
            command_line=command_line, input=input
        )
        self.actions.append(action)

    @stateful.precondition(lambda self: len(self.actions) > 0)
    @stateful.invariant()
    def run_actions(  # noqa: C901
        self,
    ) -> None:
        """Run the actions, serially and concurrently.

        Run the actions once serially, then once more concurrently with
        the faked configuration mutex, and assert that both runs yield
        identical intermediate and final results.

        We must run the concurrent version in processes, not threads or
        Python async functions, because the `click` testing machinery
        manipulates global properties (e.g. the standard I/O streams,
        the current directory, and the environment), and we require this
        manipulation to happen in a time-overlapped manner.

        However, running multiple processes increases the risk of the
        operating system imposing process count or memory limits on us.
        We therefore skip the test as a whole if we fail to start a new
        process due to lack of necessary resources (memory, processes,
        or open file descriptors).

        """
        if not TYPE_CHECKING:  # pragma: no branch
            multiprocessing = pytest.importorskip('multiprocessing')
        IPCMessage: TypeAlias = FakeConfigurationMutexStateMachine.IPCMessage
        intermediate_configs: dict[int, _types.VaultConfig] = {}
        intermediate_results: dict[
            int, tuple[bool, str | None, str | None]
        ] = {}
        true_configs: dict[int, _types.VaultConfig] = {}
        true_results: dict[int, tuple[bool, str | None, str | None]] = {}
        timeout = 5
        actions = self.actions
        mp = multiprocessing.get_context()
        # Coverage tracking writes coverage data to the current working
        # directory, but because the subprocesses are spawned within the
        # `tests.isolated_vault_config` context manager, their starting
        # working directory is the isolated one, not the original one.
        orig_cwd = pathlib.Path.cwd()

        fatal_process_creation_errnos = {
            # Specified by POSIX for fork(3).
            errno.ENOMEM,
            # Specified by POSIX for fork(3).
            errno.EAGAIN,
            # Specified by Linux/glibc for fork(3)
            getattr(errno, 'ENOSYS', errno.ENOMEM),
            # Specified by POSIX for posix_spawn(3).
            errno.EINVAL,
        }

        hypothesis.note(f'# {actions = }')

        stack = contextlib.ExitStack()
        with stack:
            runner = tests.CliRunner(mix_stderr=False)
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )
            for i, action in enumerate(actions):
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    args=action.command_line,
                    input=action.input,
                    catch_exceptions=True,
                )
                true_configs[i] = copy.copy(cli_helpers.load_config())
                true_results[i] = (
                    result.clean_exit(empty_stderr=False),
                    result.stdout,
                    result.stderr,
                )

        with stack:  # noqa: PLR1702
            runner = tests.CliRunner(mix_stderr=False)
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                tests.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={'services': {}},
                )
            )

            child_output_queue: multiprocessing.Queue[IPCMessage] = mp.Queue()
            child_input_queues: list[
                multiprocessing.Queue[IPCMessage] | None
            ] = []
            processes: list[multiprocessing.process.BaseProcess] = []
            processes_pending: set[multiprocessing.process.BaseProcess] = set()
            ready_wait: set[int] = set()

            try:
                for i, action in enumerate(actions):
                    q: multiprocessing.Queue[IPCMessage] | None = mp.Queue()
                    try:
                        p: multiprocessing.process.BaseProcess = mp.Process(
                            name=f'fake-mutex-action-{i:02d}',
                            target=run_actions_handler,
                            kwargs={
                                'id_num': i,
                                'timeout': timeout,
                                'action': action,
                                'input_queue': q,
                                'output_queue': child_output_queue,
                            },
                            daemon=False,
                        )
                        p.start()
                    except OSError as exc:  # pragma: no cover
                        if exc.errno in fatal_process_creation_errnos:
                            pytest.skip(
                                'cannot test mutex functionality due to '
                                'lack of system resources for '
                                'creating enough subprocesses'
                            )
                        raise
                    else:
                        processes.append(p)
                        processes_pending.add(p)
                        child_input_queues.append(q)
                        ready_wait.add(i)

                while processes_pending:
                    try:
                        self.mainloop(
                            timeout=timeout,
                            child_output_queue=child_output_queue,
                            child_input_queues=child_input_queues,
                            ready_wait=ready_wait,
                            intermediate_configs=intermediate_configs,
                            intermediate_results=intermediate_results,
                            processes=processes,
                            processes_pending=processes_pending,
                            block=True,
                        )
                    except Exception as exc:  # pragma: no cover
                        for i, q in enumerate(child_input_queues):
                            if q:
                                q.put(IPCMessage(i, 'exception', exc))
                        for p in processes_pending:
                            p.join(timeout=timeout)
                        raise
            finally:
                try:
                    while True:
                        try:
                            self.mainloop(
                                timeout=timeout,
                                child_output_queue=child_output_queue,
                                child_input_queues=child_input_queues,
                                ready_wait=ready_wait,
                                intermediate_configs=intermediate_configs,
                                intermediate_results=intermediate_results,
                                processes=processes,
                                processes_pending=processes_pending,
                                block=False,
                            )
                        except queue.Empty:
                            break
                finally:
                    # The subprocesses have this
                    # `tests.isolated_vault_config` directory as their
                    # startup and working directory, so systems like
                    # coverage tracking write their data files to this
                    # directory.  We need to manually move them back to
                    # the starting working directory if they are to
                    # survive this test.
                    for coverage_file in pathlib.Path.cwd().glob(
                        '.coverage.*'
                    ):
                        shutil.move(coverage_file, orig_cwd)
        hypothesis.note(
            f'# {true_results = }, {intermediate_results = }, '
            f'identical = {true_results == intermediate_results}'
        )
        hypothesis.note(
            f'# {true_configs = }, {intermediate_configs = }, '
            f'identical = {true_configs == intermediate_configs}'
        )
        assert intermediate_results == true_results
        assert intermediate_configs == true_configs

    @staticmethod
    def mainloop(
        *,
        timeout: int,
        child_output_queue: multiprocessing.Queue[
            FakeConfigurationMutexStateMachine.IPCMessage
        ],
        child_input_queues: list[
            multiprocessing.Queue[
                FakeConfigurationMutexStateMachine.IPCMessage
            ]
            | None
        ],
        ready_wait: set[int],
        intermediate_configs: dict[int, _types.VaultConfig],
        intermediate_results: dict[int, tuple[bool, str | None, str | None]],
        processes: list[multiprocessing.process.BaseProcess],
        processes_pending: set[multiprocessing.process.BaseProcess],
        block: bool = True,
    ) -> None:
        IPCMessage: TypeAlias = FakeConfigurationMutexStateMachine.IPCMessage
        msg = child_output_queue.get(block=block, timeout=timeout)
        # TODO(the-13th-letter): Rewrite using structural pattern
        # matching.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        if (  # pragma: no cover
            isinstance(msg, IPCMessage)
            and msg[1] == 'exception'
            and isinstance(msg[2], Exception)
        ):
            e = msg[2]
            raise e
        if isinstance(msg, IPCMessage) and msg[1] == 'ready':
            n = msg[0]
            ready_wait.remove(n)
            if not ready_wait:
                assert child_input_queues
                assert child_input_queues[0]
                child_input_queues[0].put(
                    IPCMessage(0, 'go', None),
                    block=True,
                    timeout=timeout,
                )
        elif isinstance(msg, IPCMessage) and msg[1] == 'config':
            n = msg[0]
            config = msg[2]
            intermediate_configs[n] = cast('_types.VaultConfig', config)
        elif isinstance(msg, IPCMessage) and msg[1] == 'result':
            n = msg[0]
            result_ = msg[2]
            result_tuple: tuple[bool, str | None, str | None] = cast(
                'tuple[bool, str | None, str | None]', result_
            )
            intermediate_results[n] = result_tuple
            child_input_queues[n] = None
            p = processes[n]
            p.join(timeout=timeout)
            assert not p.is_alive()
            processes_pending.remove(p)
            assert result_tuple[0], (
                f'action #{n} exited with an error: {result_tuple!r}'
            )
            if n + 1 < len(processes):
                next_child_input_queue = child_input_queues[n + 1]
                assert next_child_input_queue
                next_child_input_queue.put(
                    IPCMessage(n + 1, 'go', None),
                    block=True,
                    timeout=timeout,
                )
        else:
            raise AssertionError()


TestFakedConfigurationMutex = tests.skip_if_no_multiprocessing_support(
    FakeConfigurationMutexStateMachine.TestCase
)
"""The [`unittest.TestCase`][] class that will actually be run."""


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

    @Parametrize.COMPLETABLE_ITEMS
    def test_100_is_completable_item(
        self,
        partial: str,
        is_completable: bool,
    ) -> None:
        """Our `_is_completable_item` predicate for service names works."""
        assert cli_helpers.is_completable_item(partial) == is_completable

    @Parametrize.COMPLETABLE_OPTIONS
    def test_200_options(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' options."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @Parametrize.COMPLETABLE_SUBCOMMANDS
    def test_201_subcommands(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' subcommands."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @Parametrize.COMPLETABLE_PATH_ARGUMENT
    @Parametrize.INCOMPLETE
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

    @Parametrize.COMPLETABLE_SERVICE_NAMES
    def test_203_service_names(
        self,
        config: _types.VaultConfig,
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for vault service names."""
        runner = tests.CliRunner(mix_stderr=False)
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

    @Parametrize.SHELL_FORMATTER
    @Parametrize.COMPLETION_FUNCTION_INPUTS
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
        runner = tests.CliRunner(mix_stderr=False)
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

    @Parametrize.CONFIG_SETTING_MODE
    @Parametrize.SERVICE_NAME_COMPLETION_INPUTS
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
        runner = tests.CliRunner(mix_stderr=False)
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
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    ['--config', '--length=10', '--', key],
                    catch_exceptions=False,
                )
            else:
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    ['--import', '-'],
                    catch_exceptions=False,
                    input=json.dumps(config),
                )
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
        runner = tests.CliRunner(mix_stderr=False)
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
            cli_helpers.config_filename(subsystem='vault').unlink(
                missing_ok=True
            )
            assert not cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(['some_parameter']),
                '',
            )

    @Parametrize.SERVICE_NAME_EXCEPTIONS
    def test_410b_service_name_exceptions_custom_error(
        self,
        exc_type: type[Exception],
    ) -> None:
        """Service name completion quietly fails on configuration errors."""
        runner = tests.CliRunner(mix_stderr=False)
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
